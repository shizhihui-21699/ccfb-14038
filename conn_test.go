package h2

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"
)

// pipePair builds a server Conn plus the raw client end. Real TCP loopback
// connections (rather than net.Pipe) are used so the socket buffers absorb
// small write bursts: net.Pipe's strictly synchronous writes would make
// ordinary multi-frame exchanges deadlock regardless of protocol
// correctness.
func pipePair(t *testing.T) (*Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		c, err := ln.Accept()
		accepted <- acceptResult{c, err}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	res := <-accepted
	if res.err != nil {
		t.Fatalf("accept: %v", res.err)
	}
	t.Cleanup(func() { client.Close() })

	cfg := testIntegrationConfig()
	c := NewConnWithLogger(res.conn, cfg, testHandler(t), noop())
	return c, client
}

func testIntegrationConfig() *Config {
	c := DefaultConfig()
	c.GoAwayGrace = 5 * time.Second
	c.HeaderTimeout = time.Second
	c.WriteTimeout = time.Second
	return c
}

// testHandler answers 200 with a small body and echoes the request body.
// It marks the stream dispatched before doing any work, mirroring a proxy
// that has established its upstream connection.
func testHandler(t *testing.T) Handler {
	return HandlerFunc(func(r *Request, w *Responder) {
		r.MarkDispatched()
		body, _ := io.ReadAll(r.Body())
		if err := w.Headers(200, hpack.HeaderField{Name: "content-type", Value: "text/plain"}); err != nil {
			t.Errorf("Headers: %v", err)
			return
		}
		if _, err := w.Write(append([]byte("ok:"), body...)); err != nil {
			t.Errorf("Write: %v", err)
			return
		}
		if err := w.EndStream(); err != nil {
			t.Errorf("EndStream: %v", err)
		}
	})
}

// clientFramer provides raw frame I/O on the client end. A dedicated reader
// goroutine is mandatory with net.Pipe: its Write calls block until the peer
// reads, so sending and receiving cannot alternate on a single goroutine.
type clientFramer struct {
	conn net.Conn
	fr   *Reader
	fw   *Writer
	enc  *hpack.Encoder
	buf  bytes.Buffer
	mu   sync.Mutex

	frameCh chan *Frame
	readErr chan error
	// goAwayCh is closed once a GOAWAY frame is seen, carrying that frame,
	// so tests can wait for it even if the socket is torn down immediately
	// afterwards.
	goAwayCh chan *Frame
}

func newClient(t *testing.T, conn net.Conn) *clientFramer {
	t.Helper()
	cl := &clientFramer{
		conn:     conn,
		fr:       NewReader(conn, MaxFrameSizeFloor),
		fw:       NewWriter(conn, MaxFrameSizeFloor),
		frameCh:  make(chan *Frame, 64),
		readErr:  make(chan error, 1),
		goAwayCh: make(chan *Frame, 1),
	}
	cl.enc = hpack.NewEncoder(&cl.buf)
	go cl.readLoop()
	return cl
}

func (cl *clientFramer) readLoop() {
	for {
		f, err := cl.fr.ReadFrame()
		if err != nil {
			cl.readErr <- err
			return
		}
		if f.Type == FrameGoAway {
			select {
			case cl.goAwayCh <- f:
			default:
			}
		}
		cl.frameCh <- f
	}
}

// waitGoAway blocks until the reader observes GOAWAY, independent of what
// happens to the socket afterward.
func (cl *clientFramer) waitGoAway(t *testing.T) ErrorCode {
	t.Helper()
	select {
	case f := <-cl.goAwayCh:
		if f.Length < 8 {
			t.Fatalf("short GOAWAY: %d", f.Length)
		}
		return ErrorCode(beUint32(f.Payload[4:]))
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for GOAWAY")
		return ErrCodeInternal
	}
}

// nextFrame waits for one server-side frame.
func (cl *clientFramer) nextFrame(t *testing.T) *Frame {
	t.Helper()
	select {
	case f := <-cl.frameCh:
		return f
	case err := <-cl.readErr:
		t.Fatalf("frame read: %v", err)
		return nil
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for frame")
		return nil
	}
}

// pollFrame waits up to d for a frame, returning nil on timeout so a test
// can distinguish "no more frames" from a hard failure.
func (cl *clientFramer) pollFrame(d time.Duration) (*Frame, error) {
	select {
	case f := <-cl.frameCh:
		return f, nil
	case err := <-cl.readErr:
		return nil, err
	case <-time.After(d):
		return nil, nil
	}
}

func (cl *clientFramer) handshake(t *testing.T) {
	t.Helper()
	if _, err := io.WriteString(cl.conn, ClientPreface); err != nil {
		t.Fatalf("preface: %v", err)
	}
	if err := cl.fw.WriteSettings(nil); err != nil {
		t.Fatalf("client settings: %v", err)
	}
	gotAck := false
	for !gotAck {
		f := cl.nextFrame(t)
		if f.Type == FrameSettings && f.Flags.Has(FlagAck) {
			gotAck = true
		} else if f.Type == FrameSettings {
			if err := cl.fw.WriteSettingsAck(); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func (cl *clientFramer) sendHeaders(t *testing.T, streamID uint32, endStream bool, fields []hpack.HeaderField) {
	t.Helper()
	cl.mu.Lock()
	cl.buf.Reset()
	for _, f := range fields {
		if err := cl.enc.WriteField(f); err != nil {
			t.Fatal(err)
		}
	}
	block := append([]byte(nil), cl.buf.Bytes()...)
	cl.mu.Unlock()

	flags := FlagEndHeaders
	if endStream {
		flags |= FlagEndStream
	}
	if err := cl.fw.WriteRaw(FrameHeaders, flags, streamID, block); err != nil {
		t.Fatalf("send HEADERS: %v", err)
	}
}

func defaultRequestFields() []hpack.HeaderField {
	return []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "video.example"},
		{Name: ":path", Value: "/seg"},
	}
}

func readGoAway(t *testing.T, cl *clientFramer) (lastStream uint32, code ErrorCode) {
	t.Helper()
	code = cl.waitGoAway(t)
	return 0, code
}

// drainUntilHeaders consumes frames until response HEADERS for streamID
// arrive. Frames for other streams (and stray RSTs) are skipped rather than
// treated as the target, which makes the helper robust under burst traffic.
func (cl *clientFramer) drainUntilHeaders(t *testing.T, streamID uint32) {
	t.Helper()
	for {
		f := cl.nextFrame(t)
		if f.Type == FrameGoAway {
			t.Fatalf("unexpected GOAWAY while waiting for stream %d: code %s",
				streamID, ErrorCode(beUint32(f.Payload[4:])))
		}
		if f.Type == FrameHeaders && f.StreamID == streamID {
			return
		}
	}
}

// Happy path: a normal request gets a complete 200 response.
func TestIntegrationNormalRequest(t *testing.T) {
	c, raw := pipePair(t)
	defer raw.Close()
	cl := newClient(t, raw)
	serveErr := make(chan error, 1)
	go func() { serveErr <- c.Serve() }()
	cl.handshake(t)

	cl.sendHeaders(t, 1, true, defaultRequestFields())

	gotHeaders := false
	gotData := false
	for !(gotHeaders && gotData) {
		f := cl.nextFrame(t)
		switch f.Type {
		case FrameHeaders:
			gotHeaders = true
		case FrameData:
			if f.Flags.Has(FlagEndStream) {
				gotData = true
			}
		}
	}
	raw.Close()
	<-serveErr
}

// Rapid Reset over real frames: a burst of phantom open/reset cycles must
// end with GOAWAY(ENHANCE_YOUR_CALM). The test handler never calls
// MarkDispatched, so every reset is phantom by construction.
func TestIntegrationRapidResetGetsEnhanceYourCalm(t *testing.T) {
	c, raw := pipePair(t)
	c.cfg.MinSamples = 10
	c.cfg.MaxConcurrentShortStreams = 20
	c.limiter = NewAdaptiveLimiter(c.cfg)
	// Handler deliberately does NOT call MarkDispatched: these are
	// cancel-before-work streams, exactly the Rapid Reset shape.
	c.handler = HandlerFunc(func(r *Request, w *Responder) {})
	defer raw.Close()
	cl := newClient(t, raw)
	serveErr := make(chan error, 1)
	go func() { serveErr <- c.Serve() }()
	cl.handshake(t)

	// Fire cycles until a write fails (GOAWAY already closing the
	// connection) or we have sent well past the phantom cap.
	var id uint32 = 1
	for i := 0; i < 40; i++ {
		if err := cl.sendHeadersBestEffort(id); err != nil {
			break
		}
		if err := cl.fw.WriteRSTStream(id, ErrCodeCancel); err != nil {
			break
		}
		id += 2
	}

	_, code := readGoAway(t, cl)
	if code != ErrCodeEnhanceYourCalm {
		t.Fatalf("GOAWAY code=%s, want ENHANCE_YOUR_CALM", code)
	}
	raw.Close()
	<-serveErr
}

// sendHeadersBestEffort is sendHeaders that returns write errors instead of
// fatalling, used while racing a server-side GOAWAY.
func (cl *clientFramer) sendHeadersBestEffort(streamID uint32) error {
	cl.mu.Lock()
	cl.buf.Reset()
	for _, f := range defaultRequestFields() {
		if err := cl.enc.WriteField(f); err != nil {
			cl.mu.Unlock()
			return err
		}
	}
	block := append([]byte(nil), cl.buf.Bytes()...)
	cl.mu.Unlock()
	return cl.fw.WriteRaw(FrameHeaders, FlagEndHeaders|FlagEndStream, streamID, block)
}

// A seek burst (RST after the handler actually started) must leave the
// connection healthy and able to serve a subsequent request.
func TestIntegrationSeekBurstStaysHealthy(t *testing.T) {
	c, raw := pipePair(t)
	// Replace the default handler: it sends HEADERS then blocks on the
	// request context, so when the client RSTs the stream the handler was
	// definitely dispatched (non-phantom) but did not finish.
	dispatchCount := make(chan uint32, 32)
	c.handler = HandlerFunc(func(r *Request, w *Responder) {
		r.MarkDispatched() // backend work starts here, so resets are non-phantom
		_ = w.Headers(200)
		dispatchCount <- r.StreamID
		if r.StreamID == 21 {
			// Post-burst probe: answer fully so the test can see END_STREAM.
			_, _ = w.Write([]byte("healthy"))
			_ = w.EndStream()
			return
		}
		<-r.Context().Done() // emulate an in-flight segment request
	})
	defer raw.Close()
	cl := newClient(t, raw)
	serveErr := make(chan error, 1)
	go func() { serveErr <- c.Serve() }()
	cl.handshake(t)

	for i := 0; i < 10; i++ {
		id := uint32(1 + i*2)
		cl.sendHeaders(t, id, true, defaultRequestFields())
		// Wait until the handler reports dispatch, guaranteeing the reset
		// we are about to send is non-phantom.
		select {
		case got := <-dispatchCount:
			if got != id {
				t.Fatalf("dispatch id=%d, want %d", got, id)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("stream %d never dispatched", id)
		}
		// Drain the response HEADERS frame the handler just emitted.
		cl.drainUntilHeaders(t, id)
		if err := cl.fw.WriteRSTStream(id, ErrCodeCancel); err != nil {
			t.Fatal(err)
		}
	}

	if c.limiter.State() != StateNormal {
		t.Fatalf("limiter state=%v, want NORMAL after seek burst", c.limiter.State())
	}

	// A fresh request must still work.
	cl.sendHeaders(t, 21, true, defaultRequestFields())
	gotResponse := false
	for !gotResponse {
		f := cl.nextFrame(t)
		if f.Type == FrameData && f.Flags.Has(FlagEndStream) {
			gotResponse = true
		}
	}
	raw.Close()
	<-serveErr
}

// An oversized header block (raw reassembly cap) answers ENHANCE_YOUR_CALM.
func TestIntegrationHeaderBlockBomb(t *testing.T) {
	c, raw := pipePair(t)
	c.cfg.MaxHeaderBlockBytes = 64
	c.dec = NewBoundedDecoder(c.cfg)
	defer raw.Close()
	cl := newClient(t, raw)
	serveErr := make(chan error, 1)
	go func() { serveErr <- c.Serve() }()
	cl.handshake(t)

	fields := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "v.example"},
		{Name: ":path", Value: "/"},
	}
	for i := 0; i < 20; i++ {
		fields = append(fields, hpack.HeaderField{
			Name:  "x-junk-" + string(rune('a'+i)),
			Value: string(bytes.Repeat([]byte("z"), 20)),
		})
	}
	cl.sendHeaders(t, 1, true, fields)
	_, code := readGoAway(t, cl)
	if code != ErrCodeEnhanceYourCalm && code != ErrCodeCompression {
		t.Fatalf("GOAWAY code=%s, want ENHANCE_YOUR_CALM or COMPRESSION_ERROR", code)
	}
	raw.Close()
	<-serveErr
}

// A HEADERS frame never followed by END_HEADERS trips HeaderTimeout.
func TestIntegrationStalledContinuation(t *testing.T) {
	c, raw := pipePair(t)
	c.cfg.HeaderTimeout = 200 * time.Millisecond
	defer raw.Close()
	cl := newClient(t, raw)
	serveErr := make(chan error, 1)
	go func() { serveErr <- c.Serve() }()
	cl.handshake(t)

	cl.mu.Lock()
	cl.buf.Reset()
	cl.enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
	block := append([]byte(nil), cl.buf.Bytes()...)
	cl.mu.Unlock()
	// HEADERS without END_HEADERS and no CONTINUATION ever follows.
	if err := cl.fw.WriteRaw(FrameHeaders, 0, 1, block); err != nil {
		t.Fatal(err)
	}
	_, code := readGoAway(t, cl)
	if code != ErrCodeEnhanceYourCalm {
		t.Fatalf("GOAWAY code=%s, want ENHANCE_YOUR_CALM", code)
	}
	raw.Close()
	<-serveErr
}

// Protocol violations carry PROTOCOL_ERROR, proving error-code mapping.
func TestIntegrationEvenStreamIDRejected(t *testing.T) {
	c, raw := pipePair(t)
	defer raw.Close()
	cl := newClient(t, raw)
	serveErr := make(chan error, 1)
	go func() { serveErr <- c.Serve() }()
	cl.handshake(t)

	cl.sendHeaders(t, 2, true, defaultRequestFields()) // even id = illegal
	_, code := readGoAway(t, cl)
	if code != ErrCodeProtocol {
		t.Fatalf("GOAWAY code=%s, want PROTOCOL_ERROR", code)
	}
	raw.Close()
	<-serveErr
}

// Over-running the advertised concurrency cap yields per-stream
// REFUSED_STREAM, not a connection shutdown.
func TestIntegrationConcurrencyCapRefusesStreams(t *testing.T) {
	c, raw := pipePair(t)
	c.cfg.InitialMaxConcurrentStreams = 4
	c.limiter = NewAdaptiveLimiter(c.cfg)
	block := make(chan struct{})
	c.handler = HandlerFunc(func(r *Request, w *Responder) {
		<-block // hold every stream open until the test releases them
		_ = w.Headers(200)
		_ = w.EndStream()
	})
	defer raw.Close()
	cl := newClient(t, raw)
	serveErr := make(chan error, 1)
	go func() { serveErr <- c.Serve() }()
	cl.handshake(t)

	// 4 admitted (no END_STREAM so they stay open), 5th must be refused.
	for id := uint32(1); id <= 9; id += 2 {
		cl.sendHeaders(t, id, false, defaultRequestFields())
	}
	sawRefused := false
	var refusedID uint32
	// Drain whatever the server sends until the RST for stream 9 shows up
	// or the channel goes quiet; other streams send nothing because their
	// handlers are blocked.
	for {
		f, err := cl.pollFrame(500 * time.Millisecond)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if f == nil {
			break
		}
		if f.Type == FrameRSTStream && f.Length == 4 &&
			ErrorCode(beUint32(f.Payload)) == ErrCodeRefusedStream {
			sawRefused = true
			refusedID = f.StreamID
		}
	}
	if !sawRefused {
		t.Fatal("expected REFUSED_STREAM RST for over-cap stream")
	}
	if refusedID != 9 {
		t.Fatalf("refused stream id=%d, want 9", refusedID)
	}
	if c.limiter.State() != StateNormal {
		t.Fatalf("connection state=%v, want NORMAL", c.limiter.State())
	}
	close(block)
	raw.Close()
	<-serveErr
}

// A request body larger than the initial windows must flow through the
// WINDOW_UPDATE refund path without stalling: the handler drains the body,
// the read loop refunds credit, and the client can keep sending DATA.
func TestIntegrationRequestBodyFlowControl(t *testing.T) {
	c, raw := pipePair(t)
	const bodySize = 300 * 1024 // exceeds the 64 KiB default initial window
	gotBody := make(chan []byte, 1)
	c.handler = HandlerFunc(func(r *Request, w *Responder) {
		r.MarkDispatched()
		b, err := io.ReadAll(r.Body())
		if err != nil {
			t.Errorf("body read: %v", err)
		}
		gotBody <- b
		_ = w.Headers(200)
		_ = w.EndStream()
	})
	defer raw.Close()
	cl := newClient(t, raw)
	serveErr := make(chan error, 1)
	go func() { serveErr <- c.Serve() }()
	cl.handshake(t)

	// HEADERS without END_STREAM, then DATA frames.
	cl.sendHeaders(t, 1, false, defaultRequestFields())
	body := bytes.Repeat([]byte("q"), bodySize)
	chunk := MaxFrameSizeFloor
	for off := 0; off < len(body); {
		end := off + chunk
		if end > len(body) {
			end = len(body)
		}
		flags := Flags(0)
		if end == len(body) {
			flags = FlagEndStream
		}
		if err := cl.fw.WriteRaw(FrameData, flags, 1, body[off:end]); err != nil {
			t.Fatalf("data write at %d: %v", off, err)
		}
		off = end
		// Drain WINDOW_UPDATE frames so the client-side socket stays
		// readable; the server emits them as the handler consumes.
		select {
		case f := <-cl.frameCh:
			if f.Type == FrameGoAway {
				t.Fatalf("GOAWAY during upload: %s", ErrorCode(beUint32(f.Payload[4:])))
			}
		default:
		}
	}

	select {
	case b := <-gotBody:
		if len(b) != bodySize {
			t.Fatalf("handler got %d body bytes, want %d", len(b), bodySize)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler never received the full body (flow control stalled)")
	}
	raw.Close()
	<-serveErr
}

// A header block split across HEADERS + CONTINUATION frames reassembles
// correctly and still serves the request.
func TestIntegrationContinuationReassembly(t *testing.T) {
	c, raw := pipePair(t)
	defer raw.Close()
	cl := newClient(t, raw)
	serveErr := make(chan error, 1)
	go func() { serveErr <- c.Serve() }()
	cl.handshake(t)

	cl.mu.Lock()
	cl.buf.Reset()
	for _, hf := range defaultRequestFields() {
		cl.enc.WriteField(hf)
	}
	block := append([]byte(nil), cl.buf.Bytes()...)
	cl.mu.Unlock()

	// Split the block in half: HEADERS without END_HEADERS, then one
	// CONTINUATION carrying the remainder and END_HEADERS.
	mid := len(block) / 2
	if err := cl.fw.WriteRaw(FrameHeaders, 0, 1, block[:mid]); err != nil {
		t.Fatal(err)
	}
	if err := cl.fw.WriteRaw(FrameContinuation, FlagEndHeaders|FlagEndStream, 1, block[mid:]); err != nil {
		t.Fatal(err)
	}

	gotHeaders := false
	for !gotHeaders {
		f := cl.nextFrame(t)
		if f.Type == FrameHeaders {
			gotHeaders = true
		}
	}
	raw.Close()
	<-serveErr
}

// Exceeding the CONTINUATION frame cap yields ENHANCE_YOUR_CALM.
func TestIntegrationTooManyContinuations(t *testing.T) {
	c, raw := pipePair(t)
	c.cfg.MaxContinuationFrames = 2
	c.dec = NewBoundedDecoder(c.cfg)
	defer raw.Close()
	cl := newClient(t, raw)
	serveErr := make(chan error, 1)
	go func() { serveErr <- c.Serve() }()
	cl.handshake(t)

	// HEADERS plus 3 CONTINUATION frames, none ending the block in time.
	if err := cl.fw.WriteRaw(FrameHeaders, 0, 1, []byte{0x82}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := cl.fw.WriteRaw(FrameContinuation, 0, 1, []byte{0x86}); err != nil {
			t.Fatal(err)
		}
	}
	code := cl.waitGoAway(t)
	if code != ErrCodeEnhanceYourCalm {
		t.Fatalf("GOAWAY code=%s, want ENHANCE_YOUR_CALM", code)
	}
	raw.Close()
	<-serveErr
}

// PING without ACK is echoed back with ACK and the same opaque payload.
func TestIntegrationPingEcho(t *testing.T) {
	c, raw := pipePair(t)
	defer raw.Close()
	cl := newClient(t, raw)
	serveErr := make(chan error, 1)
	go func() { serveErr <- c.Serve() }()
	cl.handshake(t)

	var ping [8]byte
	ping[0] = 0xde
	ping[7] = 0xad
	if err := cl.fw.WritePing(false, ping); err != nil {
		t.Fatal(err)
	}
	for {
		f := cl.nextFrame(t)
		if f.Type == FramePing {
			if !f.Flags.Has(FlagAck) {
				t.Fatal("PING response missing ACK flag")
			}
			var echoed [8]byte
			copy(echoed[:], f.Payload)
			if echoed != ping {
				t.Fatalf("ping payload %x, want %x", echoed, ping)
			}
			break
		}
	}
	raw.Close()
	<-serveErr
}

// Malformed pseudo-header ordering is rejected per-stream without killing
// the connection (RST_STREAM, not GOAWAY).
func TestIntegrationPseudoHeaderOrdering(t *testing.T) {
	c, raw := pipePair(t)
	defer raw.Close()
	cl := newClient(t, raw)
	serveErr := make(chan error, 1)
	go func() { serveErr <- c.Serve() }()
	cl.handshake(t)

	bad := []hpack.HeaderField{
		{Name: "content-type", Value: "text/plain"}, // regular first
		{Name: ":method", Value: "GET"},             // pseudo after => illegal
		{Name: ":path", Value: "/"},
	}
	cl.sendHeaders(t, 1, true, bad)

	sawRST := false
	for {
		f, err := cl.pollFrame(time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if f == nil {
			break
		}
		if f.Type == FrameRSTStream && ErrorCode(beUint32(f.Payload)) == ErrCodeProtocol {
			sawRST = true
		}
		if f.Type == FrameGoAway {
			t.Fatalf("connection-level GOAWAY for a stream-only violation: %s",
				ErrorCode(beUint32(f.Payload[4:])))
		}
	}
	if !sawRST {
		t.Fatal("expected RST_STREAM(PROTOCOL_ERROR)")
	}
	// Connection stays usable: a valid request still works.
	cl.sendHeaders(t, 3, true, defaultRequestFields())
	gotOK := false
	for !gotOK {
		f := cl.nextFrame(t)
		if f.Type == FrameData && f.Flags.Has(FlagEndStream) {
			gotOK = true
		}
	}
	raw.Close()
	<-serveErr
}

// A late RST_STREAM for an already-closed stream is tolerated, while an
// RST on a never-opened (idle) stream is a connection PROTOCOL_ERROR.
func TestIntegrationRSTStateScope(t *testing.T) {
	c, raw := pipePair(t)
	defer raw.Close()
	cl := newClient(t, raw)
	serveErr := make(chan error, 1)
	go func() { serveErr <- c.Serve() }()
	cl.handshake(t)

	// Open and fully complete stream 1 so it enters the closed set.
	cl.sendHeaders(t, 1, true, defaultRequestFields())
	waitForEndStream(t, cl)

	// A duplicate RST on the now-closed stream must be ignored, not fatal.
	if err := cl.fw.WriteRSTStream(1, ErrCodeCancel); err != nil {
		t.Fatal(err)
	}
	// A fresh request proves the connection survived.
	cl.sendHeaders(t, 3, true, defaultRequestFields())
	waitForEndStream(t, cl)

	// An RST on a never-opened stream id kills the connection.
	if err := cl.fw.WriteRSTStream(99, ErrCodeCancel); err != nil {
		t.Fatal(err)
	}
	code := cl.waitGoAway(t)
	if code != ErrCodeProtocol {
		t.Fatalf("idle-stream RST GOAWAY code=%s, want PROTOCOL_ERROR", code)
	}
	raw.Close()
	<-serveErr
}

// waitForEndStream drains frames until an END_STREAM DATA on any stream.
func waitForEndStream(t *testing.T, cl *clientFramer) {
	t.Helper()
	for {
		f := cl.nextFrame(t)
		if f.Type == FrameGoAway {
			t.Fatalf("unexpected GOAWAY: %s", ErrorCode(beUint32(f.Payload[4:])))
		}
		if f.Type == FrameData && f.Flags.Has(FlagEndStream) {
			return
		}
	}
}

// A zero-length WINDOW_UPDATE increment is a connection PROTOCOL_ERROR.
func TestIntegrationZeroWindowUpdate(t *testing.T) {
	c, raw := pipePair(t)
	defer raw.Close()
	cl := newClient(t, raw)
	serveErr := make(chan error, 1)
	go func() { serveErr <- c.Serve() }()
	cl.handshake(t)

	var p [4]byte // increment 0
	if err := cl.fw.WriteRaw(FrameWindowUpdate, 0, 0, p[:]); err != nil {
		t.Fatal(err)
	}
	code := cl.waitGoAway(t)
	// RFC 9113 §6.9.1: a zero window increment is a PROTOCOL_ERROR.
	if code != ErrCodeProtocol {
		t.Fatalf("GOAWAY code=%s, want PROTOCOL_ERROR", code)
	}
	raw.Close()
	<-serveErr
}

// A client RST_STREAM unblocks a handler blocked writing a large response
// behind flow control — no goroutine leak via stuck writes.
func TestIntegrationClientResetUnblocksHandler(t *testing.T) {
	c, raw := pipePair(t)
	written := make(chan struct{})
	c.handler = HandlerFunc(func(r *Request, w *Responder) {
		r.MarkDispatched()
		_ = w.Headers(200)
		big := bytes.Repeat([]byte("x"), 4<<20)
		_, err := w.Write(big)
		if err == nil {
			t.Error("Write after reset returned nil, want cancellation error")
		}
		close(written)
	})
	defer raw.Close()
	cl := newClient(t, raw)
	serveErr := make(chan error, 1)
	go func() { serveErr <- c.Serve() }()
	cl.handshake(t)

	cl.sendHeaders(t, 1, true, defaultRequestFields())
	// Wait for response HEADERS so the handler is definitely inside Write,
	// then reset.
	cl.drainUntilHeaders(t, 1)
	if err := cl.fw.WriteRSTStream(1, ErrCodeCancel); err != nil {
		t.Fatal(err)
	}
	select {
	case <-written:
	case <-time.After(3 * time.Second):
		t.Fatal("handler stayed blocked after client RST_STREAM")
	}
	raw.Close()
	<-serveErr
}
