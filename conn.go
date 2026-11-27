package h2guard

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2/hpack"
)

// headerBytesHalfLife is the half-life of the compressed-header-bytes
// rate counter; the trip threshold is HeaderBytesPerSec times this
// window, so a connection may burst above the nominal rate briefly but
// not sustain it.
const headerBytesHalfLife = 5 * time.Second

// Config holds the connection's limits. The zero value is usable; see
// withDefaults for what each field defaults to.
type Config struct {
	// MaxConcurrentStreams is the initial (most generous) concurrency
	// limit, advertised in SETTINGS and used as degrade level 0.
	MaxConcurrentStreams uint32
	// DegradeLevels are the limits stepped through under pressure,
	// descending. Exhausting the reset budget at the last level sends
	// GOAWAY(ENHANCE_YOUR_CALM).
	DegradeLevels []uint32

	// HeaderTableSize is advertised as SETTINGS_HEADER_TABLE_SIZE and
	// enforced as the HPACK dynamic-table cap. Keep it small: the table
	// is per-connection memory and large tables are an attack amplifier.
	HeaderTableSize uint32
	// MaxHeaderListSize caps the decoded header list (name+value+32 per
	// field). Violations get a 431 response on that stream, not a
	// connection error.
	MaxHeaderListSize uint32
	// MaxHeaderBlockBytes caps the compressed HEADERS+CONTINUATION bytes
	// of one header block. With MaxContinuationFrames and
	// HeaderBlockTimeout this is the CONTINUATION-flood
	// (CVE-2024-27316) mitigation.
	MaxHeaderBlockBytes uint32
	// MaxContinuationFrames caps the number of CONTINUATION frames
	// following one HEADERS frame.
	MaxContinuationFrames uint32
	// MaxFrameSize is advertised as SETTINGS_MAX_FRAME_SIZE. Larger
	// frames are rejected before any allocation.
	MaxFrameSize uint32

	// HeaderBlockTimeout bounds how long a header block may stay
	// incomplete (a slow CONTINUATION trickle).
	HeaderBlockTimeout time.Duration
	// IdleTimeout closes connections that send no frames.
	IdleTimeout time.Duration
	// GoAwayGrace is how long in-flight streams get to finish after
	// GOAWAY before the TCP connection is closed.
	GoAwayGrace time.Duration

	// ResetBudgetCap is the token-bucket capacity for early resets
	// (streams reset before any response byte). ResetRefillPerSec is the
	// passive refill, ResetCompletedCredit the refund per completed
	// stream, RecoverAfter the clean time before the concurrency limit
	// steps back up one level.
	ResetBudgetCap       float64
	ResetRefillPerSec    float64
	ResetCompletedCredit float64
	RecoverAfter         time.Duration

	// HeaderBytesPerSec caps the sustained rate of compressed header
	// bytes per connection. It stops HPACK table-churn abuse (constant
	// dynamic-table inserts) that stays under the per-block limits.
	HeaderBytesPerSec float64
}

func (c *Config) withDefaults() Config {
	out := *c
	if out.MaxConcurrentStreams == 0 {
		out.MaxConcurrentStreams = 100
	}
	if len(out.DegradeLevels) == 0 {
		out.DegradeLevels = []uint32{32, 8, 1}
	}
	if out.HeaderTableSize == 0 {
		out.HeaderTableSize = 4096
	}
	if out.MaxHeaderListSize == 0 {
		out.MaxHeaderListSize = 32 << 10
	}
	if out.MaxHeaderBlockBytes == 0 {
		out.MaxHeaderBlockBytes = 32 << 10
	}
	if out.MaxContinuationFrames == 0 {
		out.MaxContinuationFrames = 32
	}
	if out.MaxFrameSize == 0 {
		out.MaxFrameSize = 16 << 10
	}
	if out.HeaderBlockTimeout == 0 {
		out.HeaderBlockTimeout = 10 * time.Second
	}
	if out.IdleTimeout == 0 {
		out.IdleTimeout = 2 * time.Minute
	}
	if out.GoAwayGrace == 0 {
		out.GoAwayGrace = 5 * time.Second
	}
	if out.ResetBudgetCap == 0 {
		out.ResetBudgetCap = 64
	}
	if out.ResetRefillPerSec == 0 {
		out.ResetRefillPerSec = 4
	}
	if out.ResetCompletedCredit == 0 {
		out.ResetCompletedCredit = 1
	}
	if out.RecoverAfter == 0 {
		out.RecoverAfter = 30 * time.Second
	}
	if out.HeaderBytesPerSec == 0 {
		out.HeaderBytesPerSec = 256 << 10
	}
	return out
}

// Conn is one HTTP/2 server-side connection.
type Conn struct {
	conn net.Conn
	br   *bufio.Reader
	fw   *frameWriter
	cfg  Config
	h    Handler

	dec *boundedDecoder

	enc    *hpack.Encoder
	encBuf bytes.Buffer
	encMu  sync.Mutex

	stats connStats
	deg   *degradeController
	// statsMu serializes access to stats, deg and headerBytes, which are
	// touched both by the read loop and by handler goroutines (via
	// streamCompleted). Never held while taking mu, and vice versa.
	statsMu sync.Mutex

	mu        sync.Mutex
	streams   map[uint32]*Stream
	maxSeen   uint32 // highest client stream ID seen
	goaway    bool
	goawayAt  time.Time
	closed    bool

	// Header-block assembly state. At most one block can be in flight
	// because CONTINUATION frames must be contiguous (RFC 7540 §6.10) —
	// which is also why a continuation flood can only ever occupy this
	// one bounded buffer.
	hb *headerBlock

	headerBytes decayCounter
	readBuf     []byte
	gotSettings bool
}

type headerBlock struct {
	streamID  uint32
	endStream bool
	frag      []byte
	frames    uint32
	deadline  time.Time
}

// NewConn wraps nc (typically a TLS connection from the listener) with
// the guarded HTTP/2 layer. h may be nil, in which case admitted streams
// are accepted but never dispatched.
func NewConn(nc net.Conn, cfg Config, h Handler) *Conn {
	cfg = cfg.withDefaults()
	levels := append([]uint32{cfg.MaxConcurrentStreams}, cfg.DegradeLevels...)
	c := &Conn{
		conn:        nc,
		br:          bufio.NewReaderSize(nc, 16<<10),
		cfg:         cfg,
		h:           h,
		stats:       newConnStats(),
		streams:     make(map[uint32]*Stream),
		headerBytes: newDecayCounter(headerBytesHalfLife),
	}
	c.fw = &frameWriter{w: nc}
	c.dec = newBoundedDecoder(cfg.HeaderTableSize, cfg.MaxHeaderListSize)
	c.enc = hpack.NewEncoder(&c.encBuf)
	c.deg = newDegradeController(degradeConfig{
		levels:          levels,
		budgetCap:       cfg.ResetBudgetCap,
		refillPerSec:    cfg.ResetRefillPerSec,
		completedCredit: cfg.ResetCompletedCredit,
		recoverAfter:    cfg.RecoverAfter,
	})
	return c
}

// Serve runs the connection's read loop until the connection closes,
// the peer misbehaves, or a rate limit forces a shutdown. The returned
// error is informational; the connection is always closed on return.
func (c *Conn) Serve() error {
	defer c.close()
	if err := c.sendSettings(c.currentMaxConcurrent()); err != nil {
		return err
	}
	if err := c.readClientPreface(); err != nil {
		return err
	}
	for {
		c.setReadDeadline()
		f, err := readFrame(c.br, c.cfg.MaxFrameSize, c.readBuf)
		if err != nil {
			if isTimeout(err) {
				if c.isGoAway() {
					return nil // drain grace expired
				}
				if c.hb != nil {
					c.shutdown(errCodeProtocol, "incomplete header block")
					return errors.New("h2guard: header block assembly timeout")
				}
				c.shutdown(errCodeNo, "idle")
				return nil
			}
			var tooBig *frameTooLargeError
			if errors.As(err, &tooBig) {
				c.shutdown(errCodeFrameSize, "frame too large")
				return tooBig
			}
			return err
		}
		c.readBuf = f.payload // keep the (possibly grown) scratch buffer
		if err := c.dispatch(f); err != nil {
			return err
		}
		c.statsMu.Lock()
		tickAction := c.deg.tick(time.Now())
		c.statsMu.Unlock()
		if tickAction == actionDegrade {
			if err := c.sendSettings(c.currentMaxConcurrent()); err != nil {
				return err
			}
		}
		if c.drained() {
			return nil
		}
	}
}

// DegradeLevel reports the connection's current punishment level (0 =
// unrestricted). Export it to metrics.
func (c *Conn) DegradeLevel() int {
	c.statsMu.Lock()
	defer c.statsMu.Unlock()
	return c.deg.level
}

// currentMaxConcurrent reads the degrade controller under its lock.
func (c *Conn) currentMaxConcurrent() uint32 {
	c.statsMu.Lock()
	defer c.statsMu.Unlock()
	return c.deg.maxConcurrent()
}

const clientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

func (c *Conn) readClientPreface() error {
	_ = c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, len(clientPreface))
	if _, err := io.ReadFull(c.br, buf); err != nil {
		return err
	}
	if string(buf) != clientPreface {
		return errors.New("h2guard: bad client preface")
	}
	return nil
}

func (c *Conn) setReadDeadline() {
	now := time.Now()
	d := now.Add(c.cfg.IdleTimeout)
	if c.hb != nil && c.hb.deadline.Before(d) {
		d = c.hb.deadline
	}
	c.mu.Lock()
	gw, gwAt := c.goaway, c.goawayAt
	c.mu.Unlock()
	if gw {
		if g := gwAt.Add(c.cfg.GoAwayGrace); g.Before(d) {
			d = g
		}
	}
	_ = c.conn.SetReadDeadline(d)
}

func (c *Conn) dispatch(f frame) error {
	if !c.gotSettings {
		// RFC 7540 §3.5: the client's first frame MUST be SETTINGS.
		if f.typ != frameSettings || f.flags&flagAck != 0 {
			return c.protocolError("first frame must be SETTINGS")
		}
		c.gotSettings = true
	}
	// While a header block is incomplete, only its CONTINUATION frames
	// are legal (RFC 7540 §6.10).
	if c.hb != nil && f.typ != frameContinuation {
		return c.protocolError("expected CONTINUATION")
	}
	switch f.typ {
	case frameHeaders:
		return c.onHeaders(f)
	case frameContinuation:
		return c.onContinuation(f)
	case frameRSTStream:
		return c.onRSTStream(f)
	case frameSettings:
		return c.onSettings(f)
	case framePing:
		return c.onPing(f)
	case frameData:
		return c.onData(f)
	case frameWindowUpdate:
		return c.onWindowUpdate(f)
	case framePushPromise:
		// Clients must not push (RFC 7540 §8.2).
		return c.protocolError("PUSH_PROMISE from client")
	case frameGoAway, framePriority:
		return nil
	default:
		// RFC 7540 §5.5: unknown frame types MUST be ignored.
		return nil
	}
}

// --- frame handlers ---

func (c *Conn) onHeaders(f frame) error {
	if f.streamID == 0 || f.streamID%2 == 0 {
		return c.protocolError("HEADERS on invalid stream")
	}
	c.mu.Lock()
	if f.streamID <= c.maxSeen {
		c.mu.Unlock()
		return c.protocolError("stream ID not increasing")
	}
	c.maxSeen = f.streamID
	c.mu.Unlock()

	payload, err := stripHeadersPrefix(f)
	if err != nil {
		return c.protocolError("malformed HEADERS")
	}
	c.beginHeaderBlock(f.streamID, f.flags&flagEndStream != 0, payload)
	if f.flags&flagEndHeaders != 0 {
		return c.finishHeaderBlock()
	}
	return nil
}

// stripHeadersPrefix removes the PADDED and PRIORITY decorations from a
// HEADERS payload, leaving the bare header-block fragment.
func stripHeadersPrefix(f frame) ([]byte, error) {
	p := f.payload
	pad := 0
	if f.flags&flagPadded != 0 {
		if len(p) < 1 {
			return nil, errors.New("missing pad length")
		}
		pad = int(p[0])
		p = p[1:]
	}
	if f.flags&flagPriority != 0 {
		if len(p) < 5 {
			return nil, errors.New("missing priority fields")
		}
		p = p[5:]
	}
	if pad > len(p) {
		return nil, errors.New("padding exceeds payload")
	}
	return p[:len(p)-pad], nil
}

func (c *Conn) beginHeaderBlock(streamID uint32, endStream bool, frag []byte) {
	c.dec.begin()
	c.hb = &headerBlock{
		streamID:  streamID,
		endStream: endStream,
		frames:    1,
		deadline:  time.Now().Add(c.cfg.HeaderBlockTimeout),
	}
	c.hb.frag = append(c.hb.frag, frag...)
}

func (c *Conn) onContinuation(f frame) error {
	if c.hb == nil || f.streamID != c.hb.streamID {
		return c.protocolError("CONTINUATION for wrong stream")
	}
	c.hb.frames++
	if c.hb.frames > c.cfg.MaxContinuationFrames+1 {
		// CONTINUATION flood (CVE-2024-27316): the peer is trickling
		// header fragments to hold memory and CPU. This is a connection
		// error; PROTOCOL_ERROR is what the major implementations send.
		return c.protocolError("too many CONTINUATION frames")
	}
	if len(c.hb.frag)+len(f.payload) > int(c.cfg.MaxHeaderBlockBytes) {
		return c.protocolError("header block too large")
	}
	c.hb.frag = append(c.hb.frag, f.payload...)
	if f.flags&flagEndHeaders != 0 {
		return c.finishHeaderBlock()
	}
	return nil
}

func (c *Conn) finishHeaderBlock() error {
	hb := c.hb
	c.hb = nil

	// HPACK state is connection-scoped: every block MUST be decoded even
	// if the stream will be refused, or the compression context desyncs.
	if err := c.dec.write(hb.frag); err != nil {
		return c.compressionError(err)
	}
	fields, err := c.dec.finish()
	if err != nil {
		if errors.Is(err, errHeaderListTooLarge) {
			return c.reject431(hb.streamID)
		}
		return c.compressionError(err)
	}

	// Rate-limit compressed header bytes: stops HPACK table churn
	// (constant dynamic-table inserts) that stays under per-block caps.
	now := time.Now()
	c.statsMu.Lock()
	headerRate := c.headerBytes.Add(float64(len(hb.frag)), now)
	c.statsMu.Unlock()
	if headerRate > c.cfg.HeaderBytesPerSec*headerBytesHalfLife.Seconds() {
		c.shutdown(errCodeEnhanceYourCalm, "header rate limit")
	}

	if !validRequestHeaders(fields) {
		return c.protocolError("invalid pseudo-headers")
	}

	c.mu.Lock()
	gw := c.goaway
	n := len(c.streams)
	c.mu.Unlock()
	if gw || uint32(n) >= c.currentMaxConcurrent() {
		// REFUSED_STREAM (RFC 7540 §7) tells the client the stream was
		// untouched and is safe to retry: a legit browser on a degraded
		// connection just retries, an attacker gets nothing.
		return c.fw.writeRSTStream(hb.streamID, errCodeRefusedStream)
	}

	s := &Stream{ID: hb.streamID, Headers: fields, EndStream: hb.endStream, conn: c}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	c.mu.Lock()
	c.streams[s.ID] = s
	c.mu.Unlock()
	c.statsMu.Lock()
	c.stats.opened.Add(1, now)
	c.statsMu.Unlock()
	if c.h != nil {
		go c.h(s)
	}
	return nil
}

// validRequestHeaders does a minimal RFC 7540 §8.1.2.3 check: the
// request pseudo-headers must be present and must come first.
func validRequestHeaders(fields []hpack.HeaderField) bool {
	var method, path, scheme bool
	seenRegular := false
	for _, f := range fields {
		if strings.HasPrefix(f.Name, ":") {
			if seenRegular {
				return false
			}
			switch f.Name {
			case ":method":
				method = true
			case ":path":
				path = true
			case ":scheme":
				scheme = true
			case ":authority":
			default:
				return false
			}
			continue
		}
		seenRegular = true
	}
	return method && path && scheme
}

func (c *Conn) onRSTStream(f frame) error {
	if f.streamID == 0 {
		return c.protocolError("RST_STREAM on stream 0")
	}
	if len(f.payload) != 4 {
		return c.frameSizeError("bad RST_STREAM length")
	}
	now := time.Now()
	c.mu.Lock()
	s, ok := c.streams[f.streamID]
	if ok {
		delete(c.streams, f.streamID)
	}
	idle := f.streamID > c.maxSeen
	c.mu.Unlock()

	if idle {
		// RFC 7540 §5.1: RST_STREAM on an idle stream is a connection
		// error. On a recently-closed stream it is a normal race.
		return c.protocolError("RST_STREAM on idle stream")
	}
	if !ok {
		return nil // late RST for an already-finished stream; harmless
	}
	s.cancel()

	if s.sentBytes.Load() > 0 {
		// The client had already received response bytes: this is the
		// browser seek / abort shape, normal on a video site. Counted
		// for observability, never punished.
		c.statsMu.Lock()
		c.stats.lateReset.Add(1, now)
		c.statsMu.Unlock()
		return nil
	}
	// Reset before any response byte: the rapid-reset shape.
	c.statsMu.Lock()
	c.stats.earlyReset.Add(1, now)
	action := c.deg.onEarlyReset(now)
	c.statsMu.Unlock()
	switch action {
	case actionDegrade:
		return c.sendSettings(c.currentMaxConcurrent())
	case actionGoAway:
		c.shutdown(errCodeEnhanceYourCalm, "stream reset rate limit")
	}
	return nil
}

func (c *Conn) onSettings(f frame) error {
	if f.streamID != 0 {
		return c.protocolError("SETTINGS on non-zero stream")
	}
	if f.flags&flagAck != 0 {
		if len(f.payload) != 0 {
			return c.frameSizeError("SETTINGS ack with payload")
		}
		return nil
	}
	if len(f.payload)%6 != 0 {
		return c.frameSizeError("bad SETTINGS length")
	}
	for i := 0; i+6 <= len(f.payload); i += 6 {
		id := binary.BigEndian.Uint16(f.payload[i:])
		val := binary.BigEndian.Uint32(f.payload[i+2:])
		switch id {
		case settingHeaderTableSize:
			// The peer's decoder table limit binds our encoder.
			c.encMu.Lock()
			c.enc.SetMaxDynamicTableSize(val)
			c.encMu.Unlock()
		case settingInitialWindowSize:
			if val > 1<<31-1 {
				// RFC 7540 §6.5.2: FLOW_CONTROL_ERROR connection error.
				c.shutdown(errCodeFlowControl, "initial window too large")
				return errors.New("h2guard: bad initial window size")
			}
		case settingEnablePush:
			if val > 1 {
				return c.protocolError("bad ENABLE_PUSH")
			}
		}
	}
	return c.fw.writeSettingsAck()
}

func (c *Conn) onPing(f frame) error {
	if f.streamID != 0 {
		return c.protocolError("PING on non-zero stream")
	}
	if len(f.payload) != 8 {
		return c.frameSizeError("bad PING length")
	}
	if f.flags&flagAck != 0 {
		return nil
	}
	var data [8]byte
	copy(data[:], f.payload)
	return c.fw.writePingAck(data)
}

func (c *Conn) onData(f frame) error {
	if f.streamID == 0 {
		return c.protocolError("DATA on stream 0")
	}
	c.mu.Lock()
	_, ok := c.streams[f.streamID]
	idle := f.streamID > c.maxSeen
	c.mu.Unlock()
	if idle {
		return c.protocolError("DATA on idle stream")
	}
	if !ok {
		return nil // raced with stream end; ignore
	}
	// This layer does not consume request bodies; keep the flow-control
	// window open so uploads don't stall. A real proxy hands these bytes
	// to the backend request body instead.
	if n := uint32(len(f.payload)); n > 0 {
		if err := c.fw.writeWindowUpdate(0, n); err != nil {
			return err
		}
		return c.fw.writeWindowUpdate(f.streamID, n)
	}
	return nil
}

func (c *Conn) onWindowUpdate(f frame) error {
	if len(f.payload) != 4 {
		return c.frameSizeError("bad WINDOW_UPDATE length")
	}
	if binary.BigEndian.Uint32(f.payload)&0x7fffffff == 0 {
		// RFC 7540 §6.9: zero increment is a PROTOCOL_ERROR.
		return c.protocolError("WINDOW_UPDATE with zero increment")
	}
	return nil
}

// --- responses, shutdown, bookkeeping ---

func (c *Conn) sendSettings(maxConcurrent uint32) error {
	return c.fw.writeSettings(
		setting{settingHeaderTableSize, c.cfg.HeaderTableSize},
		setting{settingEnablePush, 0},
		setting{settingMaxConcurrentStreams, maxConcurrent},
		setting{settingInitialWindowSize, 1 << 20},
		setting{settingMaxFrameSize, c.cfg.MaxFrameSize},
		setting{settingMaxHeaderListSize, c.cfg.MaxHeaderListSize},
	)
}

// reject431 answers an over-limit header list on that stream only, like
// an HTTP/1.1 server answering 431: one huge Cookie header from a legit
// client must not cost the connection's other streams.
func (c *Conn) reject431(streamID uint32) error {
	frag, err := c.encodeHeaders([]hpack.HeaderField{{Name: ":status", Value: "431"}})
	if err != nil {
		return err
	}
	return c.fw.writeFrame(frameHeaders, flagEndHeaders|flagEndStream, streamID, frag)
}

func (c *Conn) encodeHeaders(fields []hpack.HeaderField) ([]byte, error) {
	c.encMu.Lock()
	defer c.encMu.Unlock()
	c.encBuf.Reset()
	for _, f := range fields {
		if err := c.enc.WriteField(f); err != nil {
			return nil, err
		}
	}
	return append([]byte(nil), c.encBuf.Bytes()...), nil
}

// shutdown sends GOAWAY and starts the drain: no new streams are
// admitted, in-flight streams get GoAwayGrace to finish, then Serve
// returns and the TCP connection is closed.
func (c *Conn) shutdown(code uint32, debug string) {
	c.mu.Lock()
	if c.goaway {
		c.mu.Unlock()
		return
	}
	c.goaway = true
	c.goawayAt = time.Now()
	last := c.maxSeen
	c.mu.Unlock()
	// Bound the GOAWAY write so a non-reading peer can't hold us here.
	_ = c.conn.SetWriteDeadline(time.Now().Add(c.cfg.GoAwayGrace))
	_ = c.fw.writeGoAway(last, code, debug)
}

func (c *Conn) protocolError(why string) error {
	c.shutdown(errCodeProtocol, why)
	return fmt.Errorf("h2guard: protocol error: %s", why)
}

func (c *Conn) compressionError(err error) error {
	// RFC 7541 §4.2 / RFC 7540 §7: HPACK failures are connection errors
	// of type COMPRESSION_ERROR.
	c.shutdown(errCodeCompression, "hpack decode error")
	return fmt.Errorf("h2guard: compression error: %w", err)
}

func (c *Conn) frameSizeError(what string) error {
	c.shutdown(errCodeFrameSize, what)
	return fmt.Errorf("h2guard: frame size error: %s", what)
}

// streamCompleted is called when a stream's response has been fully
// sent. Completed streams earn reset budget back.
func (c *Conn) streamCompleted(id uint32) {
	now := time.Now()
	c.mu.Lock()
	_, ok := c.streams[id]
	delete(c.streams, id)
	c.mu.Unlock()
	if ok {
		c.statsMu.Lock()
		c.stats.completed.Add(1, now)
		c.deg.onCompleted(now)
		c.statsMu.Unlock()
	}
}

func (c *Conn) isGoAway() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.goaway
}

func (c *Conn) drained() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.goaway && len(c.streams) == 0
}

func (c *Conn) close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	streams := make([]*Stream, 0, len(c.streams))
	for _, s := range c.streams {
		streams = append(streams, s)
	}
	c.mu.Unlock()
	for _, s := range streams {
		s.cancel()
	}
	_ = c.conn.Close()
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
