package h2

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"golang.org/x/net/http2/hpack"
)

// Stream states, RFC 9113 §5.1.
type streamState uint8

const (
	stateIdle streamState = iota
	stateOpen
	stateHalfClosedLocal  // we sent END_STREAM
	stateHalfClosedRemote // peer sent END_STREAM
	stateClosed
)

// Stream is one HTTP/2 stream's bookkeeping. Fields touched by both the read
// loop and handler goroutines are guarded by mu or their own primitives.
type Stream struct {
	id    uint32
	state streamState
	mu    sync.Mutex // guards state and body bookkeeping
	conn  *Conn

	// inbound (request) flow control
	inWin *inWindow

	// outbound (response) flow control
	outWin *outWindow

	// request body: a bounded producer/consumer buffer. The producer is the
	// read loop and is inherently capped by the inbound flow-control
	// window, so a slow handler can never make this grow without bound —
	// the peer's window stops the bytes at the wire first.
	bodyMu       sync.Mutex
	bodyCond     *sync.Cond
	bodyBuf      []byte
	bodyEOF      bool
	bodyErr      error
	bodyConsumed int32 // bytes already refunded against, for coalescing

	ctx    context.Context
	cancel context.CancelCauseFunc

	// phantom is true until backend work actually starts (the handler
	// calls MarkDispatched, normally right after its backend connection is
	// established). A RST_STREAM while this is set means the client
	// cancelled before any backend work — the signal Rapid Reset
	// accounting weighs most heavily. The flag is an atomic so the read
	// loop's RST path and the handler goroutine race safely.
	phantom atomic.Bool

	// wroteHeaders guards one response per stream.
	wroteHeaders bool

	// slotReleased guards the single limiter.Release that matches the
	// single TryAcquire, regardless of whether the stream ends by RST,
	// handler return, or connection shutdown.
	slotReleased bool
}

func newStream(c *Conn, id uint32) *Stream {
	ctx, cancel := context.WithCancelCause(c.ctx)
	s := &Stream{
		id:    id,
		state: stateOpen,
		conn:  c,
		// inWin: how much the peer may send us, bounded by OUR settings.
		inWin: newInWindow(int32(c.effectiveInitialWindow())),
		// outWin: how much we may send, bounded by the PEER's settings.
		outWin: newOutWindow(int32(c.peerInitWindow)),
		ctx:    ctx,
		cancel: cancel,
	}
	s.phantom.Store(true)
	s.bodyCond = sync.NewCond(&s.bodyMu)
	return s
}

// ID returns the stream identifier.
func (s *Stream) ID() uint32 { return s.id }

// MarkDispatched records that real backend work has begun for this stream
// (typically the moment the proxy's upstream connection is established).
// After this call the stream is no longer counted as a phantom even if the
// client immediately resets it — that is the seek-burst case the limiter
// must not punish. Safe from the handler goroutine and idempotent.
func (s *Stream) MarkDispatched() { s.phantom.Store(false) }

func (s *Stream) isPhantom() bool { return s.phantom.Load() }

// setState transitions under mu, rejecting illegal transitions.
func (s *Stream) setState(next streamState) {
	s.mu.Lock()
	s.state = next
	s.mu.Unlock()
}

func (s *Stream) getState() streamState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// deliverData appends inbound DATA payload to the body buffer. Called only
// from the read loop after flow control has been charged.
func (s *Stream) deliverData(p []byte) {
	s.bodyMu.Lock()
	s.bodyBuf = append(s.bodyBuf, p...)
	s.bodyCond.Broadcast()
	s.bodyMu.Unlock()
}

// deliverEOF marks the request body complete (END_STREAM).
func (s *Stream) deliverEOF() {
	s.bodyMu.Lock()
	s.bodyEOF = true
	s.bodyCond.Broadcast()
	s.bodyMu.Unlock()
}

// abort unblocks body readers and response writers after a reset or
// connection shutdown.
func (s *Stream) abort(err error) {
	s.cancel(err)
	s.bodyMu.Lock()
	s.bodyErr = err
	s.bodyCond.Broadcast()
	s.bodyMu.Unlock()
	s.outWin.Close(err)
}

// Read implements io.Reader for the request body. Consumed bytes are
// refunded via WINDOW_UPDATE (stream + connection), coalesced so small reads
// do not produce a frame per Read call.
func (s *Stream) Read(p []byte) (int, error) {
	s.bodyMu.Lock()
	for len(s.bodyBuf) == 0 && !s.bodyEOF && s.bodyErr == nil {
		s.bodyCond.Wait()
	}
	if s.bodyErr != nil {
		err := s.bodyErr
		s.bodyMu.Unlock()
		return 0, err
	}
	if len(s.bodyBuf) == 0 && s.bodyEOF {
		s.bodyMu.Unlock()
		return 0, io.EOF
	}
	n := copy(p, s.bodyBuf)
	s.bodyBuf = s.bodyBuf[n:]
	s.bodyConsumed += int32(n)
	// Coalesce refunds: flush once a full max-frame's worth is pending, or
	// at EOF with anything outstanding.
	flush := s.bodyConsumed >= int32(s.conn.cfg.MaxFrameSize) ||
		(s.bodyEOF && len(s.bodyBuf) == 0 && s.bodyConsumed > 0)
	refund := s.bodyConsumed
	if flush {
		s.bodyConsumed = 0
	}
	s.bodyMu.Unlock()

	if flush {
		// Return the consumed credit to both inbound windows so they can
		// admit more DATA; refundInbound puts the matching WINDOW_UPDATE
		// frames on the wire.
		s.inWin.giveBack(refund)
		s.conn.inConnGiveBack(refund)
		s.conn.refundInbound(s.id, refund)
	}
	return n, nil
}

// Responder is the handler's handle to one stream's response side.
type Responder struct {
	s *Stream
}

// Headers sends response HEADERS. status is the HTTP status code; extra
// fields follow. It may be called at most once per stream.
func (w *Responder) Headers(status int, extra ...hpack.HeaderField) error {
	s := w.s
	s.mu.Lock()
	if s.wroteHeaders {
		s.mu.Unlock()
		return errors.New("h2: response headers already written")
	}
	if s.state == stateClosed || s.state == stateHalfClosedLocal {
		s.mu.Unlock()
		return errors.New("h2: write on closed stream")
	}
	s.wroteHeaders = true
	s.mu.Unlock()

	fields := append([]hpack.HeaderField{
		{Name: ":status", Value: statusItoa(status)},
	}, extra...)
	// The encoder owns a stateful dynamic table and a reusable buffer, so
	// concurrent handlers must serialize through encMu.
	s.conn.encMu.Lock()
	block := s.conn.enc.WriteFields(fields)
	blockCopy := append([]byte(nil), block...)
	s.conn.encMu.Unlock()
	s.conn.writeMu.Lock()
	defer s.conn.writeMu.Unlock()
	if err := s.conn.checkDeadline(); err != nil {
		return err
	}
	return s.conn.hbw.WriteHeaders(s.id, false, blockCopy)
}

// Write sends response DATA, honoring peer flow control at both stream and
// connection level. A zero-length or end-of-data call with endStream=true
// closes the stream.
func (w *Responder) Write(p []byte) (int, error) {
	s := w.s
	if len(p) == 0 {
		return 0, nil
	}
	written := 0
	for len(p) > 0 {
		// Reserve the smaller of the remaining payload and one frame.
		chunk := int32(len(p))
		if max := int32(s.conn.cfg.MaxFrameSize); chunk > max {
			chunk = max
		}
		// Order: connection window first, then stream window. Both may
		// wait; ctx cancellation (reset) unblocks both.
		if err := s.conn.outConn.Wait(s.ctx, chunk); err != nil {
			return written, err
		}
		if err := s.outWin.Wait(s.ctx, chunk); err != nil {
			s.conn.outConn.Add(chunk) // undo the connection reservation
			return written, err
		}
		s.conn.writeMu.Lock()
		err := s.conn.fw.WriteData(s.id, p[:chunk], false)
		s.conn.writeMu.Unlock()
		if err != nil {
			return written, err
		}
		p = p[chunk:]
		written += int(chunk)
	}
	return written, nil
}

// EndStream sends a zero-length END_STREAM DATA frame (or, if WriteHeaders
// was never called, HEADERS alone is invalid at this layer — call Headers
// first).
func (w *Responder) EndStream() error {
	s := w.s
	s.mu.Lock()
	if !s.wroteHeaders {
		s.mu.Unlock()
		return errors.New("h2: EndStream before Headers")
	}
	if s.state == stateClosed || s.state == stateHalfClosedLocal {
		s.mu.Unlock()
		return nil
	}
	s.state = stateHalfClosedLocal
	s.mu.Unlock()

	s.conn.writeMu.Lock()
	defer s.conn.writeMu.Unlock()
	if err := s.conn.checkDeadline(); err != nil {
		return err
	}
	return s.conn.fw.WriteData(s.id, nil, true)
}

// RST lets a handler terminate its own stream with an explicit error code.
func (w *Responder) RST(code ErrorCode) error {
	return w.s.conn.resetStream(w.s, code, false)
}

func statusItoa(code int) string {
	if code == 0 {
		return "200"
	}
	var buf [3]byte
	for i := len(buf) - 1; i >= 0; i-- {
		buf[i] = byte('0' + code%10)
		code /= 10
	}
	return string(buf[:])
}
