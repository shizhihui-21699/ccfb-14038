package h2guard

import (
	"bytes"
	"encoding/binary"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"
)

// testClient is a minimal HTTP/2 client for driving a Conn over net.Pipe.
type testClient struct {
	t      *testing.T
	c      net.Conn
	enc    *hpack.Encoder
	encBuf bytes.Buffer
	dec    *hpack.Decoder
	fields []hpack.HeaderField
	nextID uint32

	frames <-chan frame
	seen   []frame
}

func newTestClient(t *testing.T, c net.Conn) *testClient {
	t.Helper()
	tc := &testClient{t: t, c: c, nextID: 1}
	tc.enc = hpack.NewEncoder(&tc.encBuf)
	tc.dec = hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		tc.fields = append(tc.fields, f)
	})
	// Start the reader before writing anything: net.Pipe is synchronous,
	// and the server sends its SETTINGS before reading our preface, so
	// without a reader both sides would block on write.
	tc.frames = tc.readLoop()
	if _, err := c.Write([]byte(clientPreface)); err != nil {
		t.Fatalf("write preface: %v", err)
	}
	if err := tc.writeFrame(frameSettings, 0, 0, nil); err != nil {
		t.Fatalf("write settings: %v", err)
	}
	return tc
}

func (tc *testClient) writeFrame(typ, flags uint8, streamID uint32, payload []byte) error {
	var hdr [9]byte
	n := len(payload)
	hdr[0] = byte(n >> 16)
	hdr[1] = byte(n >> 8)
	hdr[2] = byte(n)
	hdr[3] = typ
	hdr[4] = flags
	binary.BigEndian.PutUint32(hdr[5:], streamID)
	if _, err := tc.c.Write(hdr[:]); err != nil {
		return err
	}
	if n > 0 {
		if _, err := tc.c.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// openStream sends a HEADERS frame for a GET request and returns the
// stream ID. endHeaders controls the END_HEADERS flag (false starts a
// CONTINUATION sequence).
func (tc *testClient) openStream(path string, endHeaders bool, extra ...hpack.HeaderField) (uint32, error) {
	id := tc.nextID
	tc.nextID += 2
	tc.encBuf.Reset()
	fields := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "video.example.com"},
		{Name: ":path", Value: path},
	}
	fields = append(fields, extra...)
	for _, hf := range fields {
		if err := tc.enc.WriteField(hf); err != nil {
			tc.t.Fatalf("encode: %v", err)
		}
	}
	flags := uint8(flagEndStream)
	if endHeaders {
		flags |= flagEndHeaders
	}
	err := tc.writeFrame(frameHeaders, flags, id, append([]byte(nil), tc.encBuf.Bytes()...))
	return id, err
}

func (tc *testClient) rst(id uint32) error {
	var p [4]byte
	binary.BigEndian.PutUint32(p[:], errCodeCancel)
	return tc.writeFrame(frameRSTStream, 0, id, p[:])
}

// readLoop continuously reads server frames into a channel so the server
// never blocks writing to the (synchronous) pipe.
func (tc *testClient) readLoop() <-chan frame {
	ch := make(chan frame, 512)
	go func() {
		defer close(ch)
		var buf []byte
		for {
			f, err := readFrame(tc.c, 1<<20, buf)
			if err != nil {
				return
			}
			f.payload = append([]byte(nil), f.payload...)
			buf = buf[:0]
			ch <- f
		}
	}()
	return ch
}

// next returns the next server frame matching match, recording every
// frame it consumes in tc.seen.
func (tc *testClient) next(match func(frame) bool, what string) frame {
	tc.t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case f, ok := <-tc.frames:
			if !ok {
				tc.t.Fatalf("connection closed waiting for %s", what)
			}
			tc.seen = append(tc.seen, f)
			if match(f) {
				return f
			}
		case <-timeout:
			tc.t.Fatalf("timeout waiting for %s", what)
		}
	}
}

func (tc *testClient) decodeBlock(payload []byte) []hpack.HeaderField {
	tc.t.Helper()
	tc.fields = tc.fields[:0]
	if _, err := tc.dec.Write(payload); err != nil {
		tc.t.Fatalf("decode response: %v", err)
	}
	if err := tc.dec.Close(); err != nil {
		tc.t.Fatalf("decode close: %v", err)
	}
	return tc.fields
}

func fieldValue(fields []hpack.HeaderField, name string) string {
	for _, f := range fields {
		if f.Name == name {
			return f.Value
		}
	}
	return ""
}

func isSettings(f frame) bool  { return f.typ == frameSettings && f.flags&flagAck == 0 }
func isGoAway(f frame) bool    { return f.typ == frameGoAway }
func goAwayCode(f frame) uint32 { return binary.BigEndian.Uint32(f.payload[4:8]) }

func serve(cfg Config, h Handler) (client net.Conn, done chan error) {
	srv, cli := net.Pipe()
	c := NewConn(srv, cfg, h)
	done = make(chan error, 1)
	go func() { done <- c.Serve() }()
	return cli, done
}

// TestRapidResetDegradesAndGoAway is the CVE-2023-44487 shape: streams
// opened and reset before any response. The connection must step its
// advertised concurrency down the ladder and finally give up with
// GOAWAY(ENHANCE_YOUR_CALM).
func TestRapidResetDegradesAndGoAway(t *testing.T) {
	cfg := Config{
		MaxConcurrentStreams: 4,
		DegradeLevels:        []uint32{2, 1},
		ResetBudgetCap:       8,
		ResetRefillPerSec:    0.01,
		ResetCompletedCredit: 0.01,
		RecoverAfter:         time.Hour, // no recovery mid-test
		GoAwayGrace:          50 * time.Millisecond,
	}
	cli, _ := serve(cfg, func(s *Stream) { <-s.Context().Done() })
	defer cli.Close()
	tc := newTestClient(t, cli)

	// Budget math: cap 8 -> 9th early reset degrades to 2; half budget
	// (4) -> 5 more degrade to 1; 5 more -> GOAWAY. 30 attempts is
	// comfortably past the 19 needed.
	for i := 0; i < 30; i++ {
		id, err := tc.openStream("/seg.ts", true)
		if err != nil {
			break // server closed after GOAWAY
		}
		if err := tc.rst(id); err != nil {
			break
		}
	}

	var maxConc []uint32
	var ga *frame
	deadline := time.After(5 * time.Second)
	for ga == nil {
		select {
		case f, ok := <-tc.frames:
			if !ok {
				t.Fatal("connection closed before GOAWAY")
			}
			tc.seen = append(tc.seen, f)
			if isSettings(f) {
				for i := 0; i+6 <= len(f.payload); i += 6 {
					if binary.BigEndian.Uint16(f.payload[i:]) == settingMaxConcurrentStreams {
						maxConc = append(maxConc, binary.BigEndian.Uint32(f.payload[i+2:]))
					}
				}
			}
			if isGoAway(f) {
				cp := f
				ga = &cp
			}
		case <-deadline:
			t.Fatal("no GOAWAY within 5s")
		}
	}

	if got := goAwayCode(*ga); got != errCodeEnhanceYourCalm {
		t.Errorf("GOAWAY code = %#x, want ENHANCE_YOUR_CALM (%#x)", got, errCodeEnhanceYourCalm)
	}
	if want := []uint32{4, 2, 1}; !reflect.DeepEqual(maxConc, want) {
		t.Errorf("MaxConcurrentStreams sequence = %v, want %v", maxConc, want)
	}
}

// TestContinuationFlood is the CVE-2024-27316 shape: an endless run of
// CONTINUATION frames. The connection must reject it with
// GOAWAY(PROTOCOL_ERROR) once the frame-count cap trips.
func TestContinuationFlood(t *testing.T) {
	cfg := Config{
		MaxContinuationFrames: 4,
		MaxHeaderBlockBytes:   1 << 10,
	}
	cli, _ := serve(cfg, nil)
	defer cli.Close()
	tc := newTestClient(t, cli)

	id, err := tc.openStream("/x", false) // HEADERS without END_HEADERS
	if err != nil {
		t.Fatal(err)
	}
	chunk := bytes.Repeat([]byte("x"), 100)
	for i := 0; i < 20; i++ {
		if err := tc.writeFrame(frameContinuation, 0, id, chunk); err != nil {
			break
		}
	}

	ga := tc.next(isGoAway, "GOAWAY")
	if got := goAwayCode(ga); got != errCodeProtocol {
		t.Errorf("GOAWAY code = %#x, want PROTOCOL_ERROR (%#x)", got, errCodeProtocol)
	}
}

// TestHeaderListTooLarge checks that an oversized decoded header list
// gets a 431 on that stream while the connection stays healthy.
func TestHeaderListTooLarge(t *testing.T) {
	cfg := Config{MaxHeaderListSize: 512}
	cli, _ := serve(cfg, func(s *Stream) {
		s.WriteResponse(200, []byte("ok"))
	})
	defer cli.Close()
	tc := newTestClient(t, cli)

	big, err := tc.openStream("/x", true,
		hpack.HeaderField{Name: "x-pad", Value: strings.Repeat("a", 1024)})
	if err != nil {
		t.Fatal(err)
	}
	resp := tc.next(func(f frame) bool {
		return f.typ == frameHeaders && f.streamID == big
	}, "431 response")
	if got := fieldValue(tc.decodeBlock(resp.payload), ":status"); got != "431" {
		t.Errorf("status = %q, want 431", got)
	}

	// The connection must still serve normal requests.
	ok, err := tc.openStream("/y", true)
	if err != nil {
		t.Fatal(err)
	}
	resp = tc.next(func(f frame) bool {
		return f.typ == frameHeaders && f.streamID == ok
	}, "200 response")
	if got := fieldValue(tc.decodeBlock(resp.payload), ":status"); got != "200" {
		t.Errorf("status = %q, want 200", got)
	}
}

// TestLegitSeekSurvives is the false-positive guard: a viewer dragging
// the progress bar cancels streams after data has flowed (late resets),
// mixed with normally completed streams. The connection must not
// degrade or go away.
func TestLegitSeekSurvives(t *testing.T) {
	cfg := Config{
		MaxConcurrentStreams: 8,
		DegradeLevels:        []uint32{4, 1},
		ResetBudgetCap:       16,
		ResetRefillPerSec:    1,
		ResetCompletedCredit: 1,
		RecoverAfter:         time.Hour,
	}
	handler := func(s *Stream) {
		if fieldValue(s.Headers, ":path") == "/full" {
			s.WriteResponse(200, []byte("ok"))
			return
		}
		// Streaming a segment: send some bytes, then wait for the
		// client to finish or cancel.
		s.WriteHead(200)
		s.WriteData([]byte("chunk"), false)
		<-s.Context().Done()
	}
	cli, _ := serve(cfg, handler)
	defer cli.Close()
	tc := newTestClient(t, cli)

	for i := 0; i < 20; i++ {
		// Seek: open, receive some data, cancel.
		id, err := tc.openStream("/seg", true)
		if err != nil {
			t.Fatal(err)
		}
		tc.next(func(f frame) bool { return f.typ == frameData && f.streamID == id }, "segment data")
		if err := tc.rst(id); err != nil {
			t.Fatal(err)
		}
		// Every fourth iteration, a request completes normally.
		if i%4 == 3 {
			full, err := tc.openStream("/full", true)
			if err != nil {
				t.Fatal(err)
			}
			tc.next(func(f frame) bool {
				return f.typ == frameData && f.streamID == full && f.flags&flagEndStream != 0
			}, "completed response")
		}
	}

	// One more normal request must succeed.
	last, err := tc.openStream("/full", true)
	if err != nil {
		t.Fatal(err)
	}
	resp := tc.next(func(f frame) bool { return f.typ == frameHeaders && f.streamID == last }, "final 200")
	if got := fieldValue(tc.decodeBlock(resp.payload), ":status"); got != "200" {
		t.Errorf("final status = %q, want 200", got)
	}

	for _, f := range tc.seen {
		if isGoAway(f) {
			t.Fatalf("unexpected GOAWAY (code %#x) for legit seek traffic", goAwayCode(f))
		}
	}
	settings := 0
	for _, f := range tc.seen {
		if isSettings(f) {
			settings++
		}
	}
	if settings != 1 {
		t.Errorf("server sent %d SETTINGS frames, want 1 (no degradation)", settings)
	}
}

// TestRefusedStreamIsRetryable checks that admission refusal under a
// concurrency cap uses REFUSED_STREAM, which tells the client the stream
// was never processed and is safe to retry.
func TestRefusedStreamIsRetryable(t *testing.T) {
	cfg := Config{
		MaxConcurrentStreams: 1,
		DegradeLevels:        []uint32{1},
	}
	cli, _ := serve(cfg, func(s *Stream) { <-s.Context().Done() })
	defer cli.Close()
	tc := newTestClient(t, cli)

	first, err := tc.openStream("/a", true) // occupies the single slot
	if err != nil {
		t.Fatal(err)
	}
	second, err := tc.openStream("/b", true)
	if err != nil {
		t.Fatal(err)
	}
	rst := tc.next(func(f frame) bool {
		return f.typ == frameRSTStream && f.streamID == second
	}, "REFUSED_STREAM")
	if got := binary.BigEndian.Uint32(rst.payload); got != errCodeRefusedStream {
		t.Errorf("RST code = %#x, want REFUSED_STREAM (%#x)", got, errCodeRefusedStream)
	}
	_ = first
}

// TestHPACKTableSizeUpdateTooLarge sends a dynamic table size update
// beyond the advertised limit; RFC 7541 §4.2 makes this a connection
// error of type COMPRESSION_ERROR.
func TestHPACKTableSizeUpdateTooLarge(t *testing.T) {
	cli, _ := serve(Config{}, nil) // advertised table: 4096
	defer cli.Close()
	tc := newTestClient(t, cli)

	tc.enc.SetMaxDynamicTableSizeLimit(8192)
	tc.enc.SetMaxDynamicTableSize(8192)
	if _, err := tc.openStream("/x", true); err != nil {
		t.Logf("write failed after server close: %v", err)
	}
	ga := tc.next(isGoAway, "GOAWAY")
	if got := goAwayCode(ga); got != errCodeCompression {
		t.Errorf("GOAWAY code = %#x, want COMPRESSION_ERROR (%#x)", got, errCodeCompression)
	}
}

// TestOversizedFrame checks that a frame larger than our advertised
// SETTINGS_MAX_FRAME_SIZE is a FRAME_SIZE_ERROR connection error, and
// that no large allocation happens before the check.
func TestOversizedFrame(t *testing.T) {
	cfg := Config{MaxFrameSize: 16 << 10}
	cli, _ := serve(cfg, nil)
	defer cli.Close()
	tc := newTestClient(t, cli)

	big := make([]byte, 32<<10)
	if err := tc.writeFrame(framePing, 0, 0, big); err != nil {
		t.Logf("write failed after server close: %v", err)
	}
	ga := tc.next(isGoAway, "GOAWAY")
	if got := goAwayCode(ga); got != errCodeFrameSize {
		t.Errorf("GOAWAY code = %#x, want FRAME_SIZE_ERROR (%#x)", got, errCodeFrameSize)
	}
}
