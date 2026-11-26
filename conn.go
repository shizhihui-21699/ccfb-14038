package h2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/net/http2/hpack"
)

// hopHeaders must be stripped from forwarded HTTP/2 requests (RFC 9113
// §8.2.2). We reject requests containing them rather than silently dropping
// fields, matching the standard library's strictness.
var hopHeaders = map[string]bool{
	"connection":        true,
	"keep-alive":        true,
	"proxy-connection":  true,
	"transfer-encoding": true,
	"upgrade":           true,
	"te":                true, // special-cased: "trailers" is allowed
}

// Conn is one hardened HTTP/2 connection. Create it with NewConn and drive
// it with Serve; all limits from Config are enforced on the read loop
// before any handler goroutine is created.
type Conn struct {
	raw net.Conn
	cfg *Config
	log Logger
	fr  *Reader
	fw  *Writer

	handler Handler

	limiter *AdaptiveLimiter
	dec     *BoundedDecoder
	enc     *hpackEncoder
	encMu   sync.Mutex // serializes enc, whose table/buffer are stateful
	hbw     *HeaderBlockWriter

	// write serialization for every frame leaving the connection.
	writeMu sync.Mutex

	// stream bookkeeping, touched only by the read loop.
	streams      map[uint32]*Stream
	lastPeerID   uint32 // highest client-initiated stream id seen
	lastStreamID uint32 // last stream we will process, from peer GOAWAY

	// settings we have acknowledged from the peer.
	peerMaxFrameSize uint32
	peerInitWindow   uint32
	ourInitWindow    uint32

	// outbound connection-level flow control.
	outConn *outWindow
	// inbound connection-level flow control (peer's DATA toward us).
	inConn *inWindow

	// connection lifecycle
	ctx        context.Context
	ctxCancel  context.CancelCauseFunc
	closeOnce  sync.Once
	goAwaySent bool
	goAwayMu   sync.Mutex

	// header block reassembly state
	hbReassembling bool
	hbStreamID     uint32
	hbBuf          bytes.Buffer
	hbContinuation uint32

	// graceful shutdown bookkeeping
	graceTimer *time.Timer

	// preface/settings handshake
	peerPrefaceOK    bool
	peerSettingsOK   bool
	ourSettingsAcked bool
}

// NewConn wraps an already-established TLS (or h2c-upgraded) connection. The
// caller is responsible for the TLS handshake and ALPN negotiation.
func NewConn(raw net.Conn, cfg *Config, h Handler) *Conn {
	return NewConnWithLogger(raw, cfg, h, nil)
}

// NewConnWithLogger is NewConn with an explicit Logger; pass nil to disable
// security-event logging.
func NewConnWithLogger(raw net.Conn, cfg *Config, h Handler, lg Logger) *Conn {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if lg == nil {
		lg = noop()
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	c := &Conn{
		raw:              raw,
		cfg:              cfg,
		log:              lg,
		fr:               NewReader(raw, MaxFrameSizeFloor),
		fw:               NewWriter(raw, MaxFrameSizeFloor),
		handler:          h,
		limiter:          NewAdaptiveLimiter(cfg),
		dec:              NewBoundedDecoder(cfg),
		streams:          make(map[uint32]*Stream),
		peerMaxFrameSize: MaxFrameSizeFloor,
		peerInitWindow:   65535,
		ourInitWindow:    cfg.InitialStreamWindow,
		outConn:          newOutWindow(cfg.InitialConnWindow),
		inConn:           newInWindow(cfg.InitialConnWindow),
		ctx:              ctx,
		ctxCancel:        cancel,
	}
	c.enc = newHPACKEncoder(cfg.HardMaxDynamicTableSize)
	c.hbw = NewHeaderBlockWriter(c.fw)
	return c
}

// effectiveInitialWindow returns the stream initial window currently in
// effect for new streams.
func (c *Conn) effectiveInitialWindow() uint32 { return c.ourInitWindow }

// checkDeadline applies the write timeout under writeMu.
func (c *Conn) checkDeadline() error {
	if c.cfg.WriteTimeout > 0 {
		return c.raw.SetWriteDeadline(time.Now().Add(c.cfg.WriteTimeout))
	}
	return nil
}

// Serve runs the connection until the peer closes, a fatal protocol error
// triggers GOAWAY, or the adaptive limiter escalates to CLOSING. The
// returned error is nil on orderly shutdown; otherwise it is the reason.
func (c *Conn) Serve() error {
	defer c.shutdown(nil)
	if err := c.handshake(); err != nil {
		return c.shutdown(err)
	}
	for {
		if c.ctx.Err() != nil {
			// Local lifecycle signals (peer GOAWAY, grace expiry) are
			// orderly shutdowns, not failures to report.
			cause := context.Cause(c.ctx)
			if errors.Is(cause, errPeerGoAway) || errors.Is(cause, errGraceExpired) {
				return c.shutdown(nil)
			}
			return c.shutdown(cause)
		}
		// A HEADERS block in progress is the one place where a stalled
		// peer can wedge the whole connection (every other stream's frames
		// are held behind CONTINUATION). Bound the read itself, not just
		// the inter-frame gap: a peer that sends zero bytes must still be
		// cut off at HeaderTimeout.
		if c.hbReassembling {
			_ = c.raw.SetReadDeadline(time.Now().Add(c.cfg.HeaderTimeout))
		} else {
			_ = c.raw.SetReadDeadline(time.Time{})
		}
		f, err := c.fr.ReadFrame()
		if err != nil {
			_ = c.raw.SetReadDeadline(time.Time{})
			if c.hbReassembling && isTimeoutErr(err) {
				return c.shutdown(connError(ErrCodeEnhanceYourCalm,
					"header block did not complete within HeaderTimeout"))
			}
			return c.shutdown(mapReadError(err))
		}
		if err := c.dispatch(f); err != nil {
			// A *StreamError means we already answered with RST_STREAM;
			// the connection stays healthy and the read loop continues.
			// Only *ConnError (or an I/O failure) shuts the connection.
			var se *StreamError
			if errors.As(err, &se) {
				continue
			}
			return c.shutdown(err)
		}
	}
}

// isTimeoutErr reports whether err is a net package timeout.
func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// mapReadError turns framer-level errors into the right GOAWAY code.
func mapReadError(err error) error {
	var ce *ConnError
	if errors.As(err, &ce) {
		return err
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return nil
	}
	return err
}

// handshake reads the client preface and the peer's initial SETTINGS,
// acknowledges them, and sends our own SETTINGS. Reading the preface before
// writing anything also matches the natural client-first exchange and keeps
// the two sides from deadlocking on an unbuffered transport (RFC 9113 §3.4
// permits either order of the two initial SETTINGS frames).
func (c *Conn) handshake() error {
	// Client connection preface must arrive before any frame.
	preface := make([]byte, len(ClientPreface))
	if _, err := io.ReadFull(c.raw, preface); err != nil {
		return connError(ErrCodeProtocol, "missing client connection preface")
	}
	if string(preface) != ClientPreface {
		return connError(ErrCodeProtocol, "invalid client connection preface")
	}
	c.peerPrefaceOK = true

	// First frame MUST be the peer's non-ACK SETTINGS.
	f, err := c.fr.ReadFrame()
	if err != nil {
		return mapReadError(err)
	}
	if f.Type != FrameSettings || f.Flags.Has(FlagAck) || f.StreamID != 0 || f.Length%6 != 0 {
		return connError(ErrCodeProtocol, "first frame must be non-ACK SETTINGS on stream 0")
	}
	if err := c.applySettings(f); err != nil {
		return err
	}
	c.peerSettingsOK = true

	// Now emit our SETTINGS and the connection-level window update.
	// These two go out before we read anything else, but the SETTINGS ACK
	// is sent in a separate critical section: on fully synchronous
	// transports (net.Pipe) writing three frames back-to-back while the
	// peer is still blocked on its own SETTINGS write would deadlock.
	ours := []Setting{
		{ID: SettingHeaderTableSize, Value: c.cfg.HardMaxDynamicTableSize},
		{ID: SettingInitialWindowSize, Value: c.cfg.InitialStreamWindow},
		{ID: SettingMaxFrameSize, Value: c.cfg.MaxFrameSize},
		{ID: SettingMaxConcurrentStreams, Value: c.cfg.InitialMaxConcurrentStreams},
		{ID: SettingMaxHeaderListSize, Value: c.cfg.MaxHeaderListSize},
	}
	c.writeMu.Lock()
	if err := c.checkDeadline(); err != nil {
		c.writeMu.Unlock()
		return err
	}
	if err := c.fw.WriteSettings(ours); err != nil {
		c.writeMu.Unlock()
		return err
	}
	// Connection-level initial window: RFC default is 65535, so advertise
	// only the delta.
	if delta := c.cfg.InitialConnWindow - 65535; delta > 0 {
		if err := c.fw.WriteWindowUpdate(0, uint32(delta)); err != nil {
			c.writeMu.Unlock()
			return err
		}
	}
	c.writeMu.Unlock()
	return c.writeAck()
}

func (c *Conn) writeAck() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.checkDeadline(); err != nil {
		return err
	}
	return c.fw.WriteSettingsAck()
}

// dispatch routes one frame to its handler and enforces the connection-
// level frame rules (stream-id legality, continuation locking, etc.).
func (c *Conn) dispatch(f *Frame) error {
	if c.hbReassembling && f.Type != FrameContinuation {
		// A HEADERS block in progress blocks every other frame. This is
		// the state the CVE-2024-27316 attack abuses; the HeaderTimeout
		// makes it fail closed instead of stalling forever.
		return connError(ErrCodeProtocol,
			fmt.Sprintf("%s frame while expecting CONTINUATION", f.Type))
	}
	// Stream-id legality per frame type (RFC 9113 §6).
	switch f.Type {
	case FrameSettings, FramePing, FrameGoAway:
		if f.StreamID != 0 {
			return connError(ErrCodeProtocol, f.Type.String()+" must be on stream 0")
		}
	case FrameWindowUpdate:
		// stream 0 or any active stream — checked below.
	case FrameContinuation:
		if f.StreamID == 0 || !c.hbReassembling || f.StreamID != c.hbStreamID {
			return connError(ErrCodeProtocol, "CONTINUATION without matching HEADERS")
		}
	case FrameHeaders, FrameData, FrameRSTStream, FramePriority, FramePushPromise:
		if f.StreamID == 0 {
			return connError(ErrCodeProtocol, f.Type.String()+" must not be on stream 0")
		}
	}

	switch f.Type {
	case FrameSettings:
		return c.handleSettings(f)
	case FramePing:
		return c.handlePing(f)
	case FrameGoAway:
		return c.handleGoAway(f)
	case FrameWindowUpdate:
		return c.handleWindowUpdate(f)
	case FrameRSTStream:
		return c.handleRST(f)
	case FrameHeaders:
		return c.handleHeaders(f)
	case FrameContinuation:
		return c.handleContinuation(f)
	case FrameData:
		return c.handleData(f)
	case FramePriority:
		return c.handlePriority(f)
	case FramePushPromise:
		// Only a server may send PUSH_PROMISE; one from a client is a
		// connection-level PROTOCOL_ERROR.
		return connError(ErrCodeProtocol, "PUSH_PROMISE sent by client")
	default:
		// Unknown frame types are ignored (RFC 9113 §5.5).
		return nil
	}
}

// ---- frame handlers -------------------------------------------------------

func (c *Conn) handleSettings(f *Frame) error {
	if f.Flags.Has(FlagAck) {
		if f.Length != 0 {
			return connError(ErrCodeFrameSize, "SETTINGS ACK with payload")
		}
		c.ourSettingsAcked = true
		return nil
	}
	if f.Length%6 != 0 {
		return connError(ErrCodeFrameSize, "SETTINGS payload not a multiple of 6")
	}
	if err := c.applySettings(f); err != nil {
		return err
	}
	return c.writeAck()
}

// applySettings validates and applies one non-ACK SETTINGS frame. Every
// range error maps to the code RFC 9113 §6.5.2 names for that identifier.
func (c *Conn) applySettings(f *Frame) error {
	p := f.Payload
	for len(p) > 0 {
		id := uint16(p[0])<<8 | uint16(p[1])
		val := uint32(p[2])<<24 | uint32(p[3])<<16 | uint32(p[4])<<8 | uint32(p[5])
		p = p[6:]
		switch id {
		case SettingHeaderTableSize:
			if val > c.cfg.HardMaxDynamicTableSize {
				// Peer wants a bigger table than our hard cap: clamp it
				// rather than killing the connection. The encoder we use
				// toward the peer and the decoder it uses toward us are
				// both bounded.
				val = c.cfg.HardMaxDynamicTableSize
			}
			c.enc.SetMaxDynamicTableSize(val)
		case SettingEnablePush:
			if val != 0 && val != 1 {
				return connError(ErrCodeProtocol, "ENABLE_PUSH not 0 or 1")
			}
			// We are a server-side proxy that never pushes; accept 0.
			if val == 1 {
				return connError(ErrCodeProtocol, "server-side proxy does not enable push")
			}
		case SettingInitialWindowSize:
			if val > maxWindow {
				return connError(ErrCodeFlowControl, "INITIAL_WINDOW_SIZE above 2^31-1")
			}
			// This is the peer telling US how much WE may send, i.e. it
			// governs the outbound (response) window of every stream and
			// streams created later.
			old := c.peerInitWindow
			c.peerInitWindow = val
			for _, s := range c.streams {
				s.outWin.SetInitial(old, val)
			}
		case SettingMaxFrameSize:
			if val < MaxFrameSizeFloor || val > MaxFrameSizeCeiling {
				return connError(ErrCodeFrameSize, "MAX_FRAME_SIZE out of range")
			}
			c.peerMaxFrameSize = val
			// Frames the peer sends us may now be larger...
			c.fr.SetMaxFrameSize(val)
			// ...and frames we send must not exceed what it can accept.
			c.fw.maxFrameSize = val
		case SettingMaxConcurrentStreams:
			// Advisory toward us; our limiter is the authority. Remember
			// it but never exceed our own configured cap.
			// No action needed beyond acceptance.
		case SettingMaxHeaderListSize:
			// Advisory; our hard caps are the authority.
		default:
			// Unknown identifiers are ignored (§6.5.3).
		}
	}
	return nil
}

func (c *Conn) handlePing(f *Frame) error {
	if f.Flags.Has(FlagAck) {
		return nil // unsolicited ACKs are ignored
	}
	if f.Length != 8 {
		return connError(ErrCodeFrameSize, "PING payload must be 8 octets")
	}
	var data [8]byte
	copy(data[:], f.Payload)
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.checkDeadline(); err != nil {
		return err
	}
	return c.fw.WritePing(true, data)
}

func (c *Conn) handleGoAway(f *Frame) error {
	if f.Length < 8 {
		return connError(ErrCodeFrameSize, "GOAWAY shorter than 8 octets")
	}
	last := beUint32(f.Payload[0:]) & 0x7fffffff
	code := ErrorCode(beUint32(f.Payload[4:]))
	c.log.Printf("peer GOAWAY code=%s lastStream=%d", code, last)
	c.goAwayMu.Lock()
	c.lastStreamID = last
	c.goAwayMu.Unlock()
	// Streams above last were never processed by the peer; handlers still
	// running on lower ids get to finish (§6.8). New streams above last
	// are refused in handleHeaders, and the grace timer closes the socket
	// once in-flight work has had its chance.
	c.ctxCancel(errPeerGoAway)
	if c.cfg.GoAwayGrace > 0 {
		c.graceTimer = time.AfterFunc(c.cfg.GoAwayGrace, func() {
			c.ctxCancel(errGraceExpired)
		})
	}
	return nil
}

func (c *Conn) handleWindowUpdate(f *Frame) error {
	if f.Length != 4 {
		return connError(ErrCodeFrameSize, "WINDOW_UPDATE payload must be 4 octets")
	}
	inc := beUint32(f.Payload) & 0x7fffffff
	if inc == 0 {
		return c.frameOrStreamError(f.StreamID, ErrCodeProtocol, "zero WINDOW_UPDATE increment")
	}
	if f.StreamID == 0 {
		return c.outConn.Add(int32(inc))
	}
	s := c.streams[f.StreamID]
	if s == nil {
		// Updates on idle/closed streams are tolerated when the id is in
		// the historical range; an id beyond what we've used is a
		// PROTOCOL_ERROR.
		if f.StreamID > c.lastPeerID {
			return connError(ErrCodeProtocol, "WINDOW_UPDATE on unknown stream")
		}
		return nil
	}
	return s.outWin.Add(int32(inc))
}

func (c *Conn) handleRST(f *Frame) error {
	if f.Length != 4 {
		return connError(ErrCodeFrameSize, "RST_STREAM payload must be 4 octets")
	}
	s := c.streams[f.StreamID]
	if s == nil {
		// The stream is either idle (never opened) or already closed.
		// RFC 9113 §6.4: RST on an idle stream is a PROTOCOL_ERROR; a
		// late RST for a closed stream is harmless and must be ignored.
		if c.wasEverOpened(f.StreamID) {
			return nil
		}
		return connError(ErrCodeProtocol, "RST_STREAM on idle stream")
	}
	phantom := s.isPhantom()
	ev := c.limiter.RecordReset(phantom)
	// finishStream performs the single matching limiter.Release.
	c.finishStream(s, streamError(s.id, ErrCodeCancel, "client RST_STREAM"))
	return c.onLimiterEvent(ev)
}

// wasEverOpened reports whether a stream id was previously admitted (and
// possibly since removed from the live map on close). Client streams are
// odd and strictly increasing, so every odd id at or below lastPeerID was
// opened at some point.
func (c *Conn) wasEverOpened(id uint32) bool {
	return id%2 == 1 && id <= c.lastPeerID
}

func (c *Conn) handlePriority(f *Frame) error {
	// PRIORITY is deprecated in RFC 9113 but must still be syntactically
	// accepted so naive clients don't kill the connection.
	if f.Length != 5 {
		return connError(ErrCodeFrameSize, "PRIORITY payload must be 5 octets")
	}
	return nil
}

// handleHeaders opens (or, in the CONTINUATION case, reassembles) a stream.
func (c *Conn) handleHeaders(f *Frame) error {
	id := f.StreamID
	// Client streams are odd and strictly increasing.
	if id%2 == 0 {
		return connError(ErrCodeProtocol, "client-initiated stream id must be odd")
	}
	if id <= c.lastPeerID {
		// Reuse of an existing or closed stream id.
		return connError(ErrCodeProtocol, "non-idle stream id reused")
	}
	if _, exists := c.streams[id]; exists {
		return connError(ErrCodeProtocol, "duplicate HEADERS on live stream")
	}

	// Peer GOAWAY told us not to process ids above its last-stream.
	c.goAwayMu.Lock()
	last := c.lastStreamID
	c.goAwayMu.Unlock()
	if last != 0 && id > last {
		_ = c.resetNewStream(id, ErrCodeRefusedStream, "stream above peer GOAWAY last id")
		return nil
	}

	// Admission control: limiter first (Rapid Reset cap), then accounting.
	if !c.limiter.TryAcquire() {
		// REFUSED_STREAM: explicitly retryable, so a well-behaved browser
		// retries on another connection rather than showing an error.
		c.log.Printf("stream %d refused: effective cap %d reached, state=%s",
			id, c.limiter.EffectiveLimit(), c.limiter.State())
		_ = c.resetNewStream(id, ErrCodeRefusedStream, "adaptive concurrency limit reached")
		return nil
	}
	ev := c.limiter.RecordOpen()
	if ev == EventClosing {
		c.limiter.Release()
		return c.onLimiterEvent(ev)
	}

	// Begin reassembly. Even a HEADERS with END_HEADERS goes through the
	// same bounded buffer so the accounting is uniform.
	c.hbReassembling = true
	c.hbStreamID = id
	c.hbBuf.Reset()
	c.hbContinuation = 0
	return c.appendHeaderPayload(f)
}

func (c *Conn) handleContinuation(f *Frame) error {
	// The read deadline in Serve enforces HeaderTimeout; here we only
	// bound the number of frames so a fast-streaming CONTINUATION flood
	// cannot bypass the wall clock by sending back-to-back.
	c.hbContinuation++
	if c.hbContinuation > c.cfg.MaxContinuationFrames {
		return connError(ErrCodeEnhanceYourCalm,
			fmt.Sprintf("more than %d CONTINUATION frames per header block", c.cfg.MaxContinuationFrames))
	}
	return c.appendHeaderPayload(f)
}

// appendHeaderPayload strips PADDED/PRIORITY wrappers, accumulates the pure
// HPACK block, and finalizes at END_HEADERS.
func (c *Conn) appendHeaderPayload(f *Frame) error {
	p := f.Payload
	if f.Flags.Has(FlagPadded) {
		if len(p) < 1 {
			return connError(ErrCodeProtocol, "PADDING flag without pad length")
		}
		padLen := int(p[0])
		p = p[1:]
		if padLen >= len(p) {
			return connError(ErrCodeProtocol, "padding longer than payload")
		}
		p = p[:len(p)-padLen]
	}
	if f.Type == FrameHeaders && f.Flags.Has(FlagPriority) {
		if len(p) < 5 {
			return connError(ErrCodeProtocol, "PRIORITY flag without 5 dependency octets")
		}
		p = p[5:]
	}
	if uint32(c.hbBuf.Len()+len(p)) > c.cfg.MaxHeaderBlockBytes {
		return connError(ErrCodeEnhanceYourCalm,
			"reassembled header block exceeds MaxHeaderBlockBytes")
	}
	c.hbBuf.Write(p)

	if !f.Flags.Has(FlagEndHeaders) {
		return nil
	}
	// Block complete: decode under all hard caps, validate, dispatch.
	return c.finalizeHeaders(f.Flags)
}

// finalizeHeaders decodes and validates the reassembled block and starts
// the handler goroutine.
func (c *Conn) finalizeHeaders(flags Flags) error {
	block := c.hbBuf.Bytes()
	id := c.hbStreamID
	c.hbReassembling = false
	c.hbStreamID = 0

	c.dec.BeginBlock()
	fields, err := c.dec.Decode(block)
	if err != nil {
		// The stream never entered c.streams; this is the single release
		// matching the TryAcquire in handleHeaders.
		c.limiter.Release()
		var de hpack.DecodingError
		if errors.As(err, &de) {
			// Malformed HPACK state: the compression context is now
			// unrecoverable, the RFC-mandated answer is COMPRESSION_ERROR.
			return connError(ErrCodeCompression, de.Error())
		}
		if errors.Is(err, ErrHPACKBudget) {
			// Valid encoding, excessive resources: ENHANCE_YOUR_CALM.
			return connError(ErrCodeEnhanceYourCalm, err.Error())
		}
		return connError(ErrCodeCompression, err.Error())
	}
	req, err := c.validateHeaders(id, fields)
	if err != nil {
		// validateHeaders already emitted (or queued) the RST_STREAM;
		// only the limiter slot remains to clean up.
		c.limiter.Release()
		return err
	}

	s := newStream(c, id)
	if !flags.Has(FlagEndStream) {
		s.setState(stateOpen)
	} else {
		s.setState(stateHalfClosedRemote)
		s.deliverEOF()
	}
	c.streams[id] = s
	c.lastPeerID = id

	c.dispatchHandler(s, req)
	return nil
}

// validateHeaders enforces the HTTP/2 message framing rules of RFC 9113
// §8.3 and returns a populated Request.
func (c *Conn) validateHeaders(id uint32, fields []hpack.HeaderField) (*Request, error) {
	req := &Request{StreamID: id, Headers: fields}
	var pseudoSeen map[string]bool
	regularStarted := false
	for _, hf := range fields {
		name := hf.Name
		if len(name) == 0 {
			return nil, c.resetNewStream(id, ErrCodeProtocol, "empty header name")
		}
		isPseudo := len(name) > 0 && name[0] == ':'
		if isPseudo {
			if regularStarted {
				return nil, c.resetNewStream(id, ErrCodeProtocol,
					"pseudo-header after regular header field")
			}
			if pseudoSeen == nil {
				pseudoSeen = make(map[string]bool)
			}
			if pseudoSeen[name] {
				return nil, c.resetNewStream(id, ErrCodeProtocol,
					"duplicate pseudo-header "+name)
			}
			pseudoSeen[name] = true
			switch name {
			case ":method":
				req.Method = hf.Value
			case ":scheme":
				req.Scheme = hf.Value
			case ":authority":
				req.Authority = hf.Value
			case ":path":
				req.Path = hf.Value
			default:
				return nil, c.resetNewStream(id, ErrCodeProtocol,
					"unknown pseudo-header "+name)
			}
			continue
		}
		regularStarted = true
		lower := name
		if !isLowerASCII(name) {
			return nil, c.resetNewStream(id, ErrCodeProtocol,
				"header field name must be lowercase: "+name)
		}
		if hopHeaders[lower] {
			if lower == "te" && hf.Value == "trailers" {
				continue
			}
			return nil, c.resetNewStream(id, ErrCodeProtocol,
				"forbidden hop-by-hop header: "+name)
		}
	}
	if req.Method == "" {
		return nil, c.resetNewStream(id, ErrCodeProtocol, "missing :method")
	}
	if req.Method != "CONNECT" {
		if req.Scheme == "" {
			return nil, c.resetNewStream(id, ErrCodeProtocol, "missing :scheme")
		}
		if req.Path == "" {
			return nil, c.resetNewStream(id, ErrCodeProtocol, "missing :path")
		}
	}
	return req, nil
}

func isLowerASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch >= 'A' && ch <= 'Z' {
			return false
		}
	}
	return true
}

func (c *Conn) handleData(f *Frame) error {
	s := c.streams[f.StreamID]
	payload := f.Payload
	if f.Flags.Has(FlagPadded) {
		if len(payload) < 1 {
			return connError(ErrCodeProtocol, "PADDING flag without pad length")
		}
		padLen := int(payload[0])
		payload = payload[1:]
		if padLen > len(payload) {
			return connError(ErrCodeProtocol, "padding longer than DATA payload")
		}
		payload = payload[:len(payload)-padLen]
	}
	dataLen := int32(len(payload))

	if s == nil {
		// A stream never admitted is idle: DATA there is a connection-level
		// PROTOCOL_ERROR (RFC 9113 §8.1). A previously opened but now
		// closed stream answers STREAM_CLOSED with RST_STREAM.
		if !c.wasEverOpened(f.StreamID) {
			return connError(ErrCodeProtocol, "DATA on idle stream")
		}
		return c.resetNewStream(f.StreamID, ErrCodeStreamClosed, "DATA on closed stream")
	}

	state := s.getState()
	if state == stateHalfClosedRemote {
		// Peer already sent END_STREAM: any further DATA on this stream is
		// a half-closed (remote) protocol error.
		return c.resetStream(s, ErrCodeStreamClosed, true)
	}
	if state == stateClosed {
		return c.resetNewStream(f.StreamID, ErrCodeStreamClosed, "DATA on closed stream")
	}

	// Flow control: zero-length DATA consumes no window (RFC 9113 §6.9.1).
	if dataLen > 0 {
		if err := s.inWin.Take(dataLen); err != nil {
			return err
		}
		// Connection-level inbound window is tracked alongside the
		// per-stream window and charged from the read loop.
		if err := c.inConnTake(dataLen); err != nil {
			return err
		}
		s.deliverData(payload)
	}
	if f.Flags.Has(FlagEndStream) {
		s.setState(stateHalfClosedRemote)
		s.deliverEOF()
	}
	return nil
}

// inConn tracks the inbound connection window alongside per-stream windows.
// It is kept as a method pair so the numbers live next to the framer.
func (c *Conn) inConnTake(n int32) error { return c.inConn.Take(n) }

func (c *Conn) inConnGiveBack(n int32) { c.inConn.giveBack(n) }

// refundInbound returns flow-control credit after handler consumption.
func (c *Conn) refundInbound(streamID uint32, n int32) {
	if n <= 0 {
		return
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.checkDeadline(); err != nil {
		return
	}
	// Stream-level update first; a failed connection write leaves the
	// stream slightly conservative, which is always safe.
	_ = c.fw.WriteWindowUpdate(streamID, uint32(n))
	_ = c.fw.WriteWindowUpdate(0, uint32(n))
}

// ---- stream lifecycle -----------------------------------------------------

// dispatchHandler runs one request on its own goroutine, exactly as the
// original proxy did — but now the goroutine only exists after every
// admission and header-budget check has passed, so an attacker cannot create
// one per HEADERS frame at will. The stream stays phantom until the handler
// calls r.MarkDispatched() (i.e. its backend work really started); this is
// what separates a Rapid Reset cancel-before-work from a seek cancel of a
// request the proxy was already serving.
func (c *Conn) dispatchHandler(s *Stream, req *Request) {
	req.stream = s
	go func() {
		defer c.handlerDone(s)
		resp := &Responder{s: s}
		// A panicking handler must never take down the read loop.
		defer func() {
			if r := recover(); r != nil {
				_ = c.resetStream(s, ErrCodeInternal, false)
			}
		}()
		c.handler.ServeHTTP(req, resp)
	}()
}

// handlerDone releases limiter credit and, if the handler ended without an
// explicit terminal frame, closes the stream cleanly.
func (c *Conn) handlerDone(s *Stream) {
	state := s.getState()
	if state != stateClosed && state != stateHalfClosedLocal {
		// Best-effort terminal frame; ignore write errors on a dying conn.
		c.writeMu.Lock()
		_ = c.fw.WriteData(s.id, nil, true)
		c.writeMu.Unlock()
		s.setState(stateHalfClosedLocal)
	}
	// If the read loop already tore the stream down (RST/GOAWAY), the
	// slot was released by finishStream; the guard prevents a double free.
	c.releaseSlot(s)
}

// releaseSlot returns the limiter slot acquired for s exactly once.
func (c *Conn) releaseSlot(s *Stream) {
	s.mu.Lock()
	if s.slotReleased {
		s.mu.Unlock()
		return
	}
	s.slotReleased = true
	s.mu.Unlock()
	c.limiter.Release()
}

// finishStream removes a stream after RST/abort and wakes its handler.
func (c *Conn) finishStream(s *Stream, err error) {
	if _, ok := c.streams[s.id]; ok {
		delete(c.streams, s.id)
	}
	s.setState(stateClosed)
	s.abort(err)
	c.releaseSlot(s)
}

// resetStream sends RST_STREAM for a live stream and tears it down.
func (c *Conn) resetStream(s *Stream, code ErrorCode, fromPeer bool) error {
	c.writeMu.Lock()
	if err := c.checkDeadline(); err == nil {
		_ = c.fw.WriteRSTStream(s.id, code)
	}
	c.writeMu.Unlock()
	c.finishStream(s, streamError(s.id, code, "local reset"))
	return nil
}

// resetNewStream answers RST_STREAM for a stream that never made it into the
// map (validation failures, admission refusal). No limiter slot is held by
// callers that pass already-released paths.
func (c *Conn) resetNewStream(id uint32, code ErrorCode, reason string) error {
	c.writeMu.Lock()
	if err := c.checkDeadline(); err == nil {
		_ = c.fw.WriteRSTStream(id, code)
	}
	c.writeMu.Unlock()
	return streamError(id, code, reason)
}

// frameOrStreamError picks connection vs stream scope: stream 0 problems are
// always connection errors; stream-scoped protocol issues use RST_STREAM.
func (c *Conn) frameOrStreamError(id uint32, code ErrorCode, reason string) error {
	if id == 0 {
		return connError(code, reason)
	}
	if s := c.streams[id]; s != nil {
		return c.resetStream(s, code, false)
	}
	return c.resetNewStream(id, code, reason)
}

// onLimiterEvent translates a limiter transition into protocol action.
// DEGRADED is silent at the wire level (the cap simply drops); CLOSING sends
// GOAWAY(ENHANCE_YOUR_CALM) so the peer knows this is an overload signal,
// not a crash, and browsers can migrate in-flight requests.
func (c *Conn) onLimiterEvent(ev LimiterEvent) error {
	switch ev {
	case EventDegraded:
		s := c.limiter.Stats()
		c.log.Printf("connection DEGRADED: opens=%d resets=%d phantom=%d ratio=%.2f cap=%d",
			s.Opens, s.Resets, s.Phantom, s.ResetRatio, s.EffectiveCap)
		return nil
	case EventClosing:
		s := c.limiter.Stats()
		c.log.Printf("connection CLOSING: opens=%d resets=%d phantom=%d ratio=%.2f",
			s.Opens, s.Resets, s.Phantom, s.ResetRatio)
		return c.sendGoAway(ErrCodeEnhanceYourCalm,
			"rapid reset pattern detected; connection being closed")
	default:
		return nil
	}
}

// sendGoAway emits a GOAWAY with the highest stream we will process and
// starts the drain timer. Idempotent.
func (c *Conn) sendGoAway(code ErrorCode, debug string) error {
	c.goAwayMu.Lock()
	if c.goAwaySent {
		c.goAwayMu.Unlock()
		return nil
	}
	c.goAwaySent = true
	last := c.lastPeerID
	c.goAwayMu.Unlock()

	c.writeMu.Lock()
	if err := c.checkDeadline(); err == nil {
		_ = c.fw.WriteGoAway(last, code, []byte(debug))
	}
	c.writeMu.Unlock()

	c.ctxCancel(fmt.Errorf("goaway %s: %s", code, debug))
	if c.cfg.GoAwayGrace > 0 {
		c.graceTimer = time.AfterFunc(c.cfg.GoAwayGrace, func() {
			c.ctxCancel(errGraceExpired)
		})
	}
	return nil
}

var errGraceExpired = errors.New("h2: GOAWAY grace period expired")
var errPeerGoAway = errors.New("h2: peer initiated GOAWAY")

// shutdown is the single teardown path: send GOAWAY for fatal errors if we
// have not already, cancel every stream, close the socket.
func (c *Conn) shutdown(serveErr error) error {
	c.closeOnce.Do(func() {
		if c.graceTimer != nil {
			c.graceTimer.Stop()
		}
		// Map a fatal error to its wire code and send GOAWAY once.
		code := ErrCodeInternal
		var ce *ConnError
		if errors.As(serveErr, &ce) {
			code = ce.Code
		}
		if serveErr != nil && !c.goAwaySent && c.peerSettingsOK {
			// Best effort; a dead socket cannot take it.
			c.goAwayMu.Lock()
			c.goAwaySent = true
			c.goAwayMu.Unlock()
			c.writeMu.Lock()
			_ = c.fw.WriteGoAway(c.lastPeerID, code, nil)
			c.writeMu.Unlock()
		}
		c.ctxCancel(serveErr)
		// Abort every still-live stream so handler goroutines unblock.
		for _, s := range c.streams {
			s.abort(serveErr)
		}
		_ = c.raw.Close()
	})
	if serveErr != nil {
		return serveErr
	}
	return nil
}

func beUint32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
