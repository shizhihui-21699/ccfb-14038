package h2guard

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"

	"golang.org/x/net/http2/hpack"
)

// Handler is called in its own goroutine for every admitted stream. The
// number of live Handler goroutines is bounded by the connection's
// current (possibly degraded) MaxConcurrentStreams, because admission
// happens before the goroutine starts.
type Handler func(s *Stream)

// Stream is a fully-received request header block. A stream only exists
// once END_HEADERS has arrived and admission control has passed — until
// then the request costs the proxy a few bytes of assembler state, no
// goroutine, and no backend work, which is what makes rapid-reset cheap
// to absorb.
type Stream struct {
	ID      uint32
	Headers []hpack.HeaderField
	// EndStream reports whether the client ended the stream with its
	// HEADERS (typical for GETs).
	EndStream bool

	conn   *Conn
	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	responded bool
	sentBytes atomic.Int64 // response DATA bytes written; drives early/late reset classification
}

// Context is canceled when the peer resets the stream, the connection
// goes away, or the connection closes. Handlers should select on it
// while talking to the backend.
func (s *Stream) Context() context.Context { return s.ctx }

// WriteHead sends the response header block. It does not end the stream.
// The encoded block must fit in one MaxFrameSize frame; keep extra
// response headers small or split them into a trailing HEADERS.
func (s *Stream) WriteHead(status int, extra ...hpack.HeaderField) error {
	s.mu.Lock()
	if s.responded {
		s.mu.Unlock()
		return errors.New("h2guard: response headers already written")
	}
	s.responded = true
	s.mu.Unlock()

	fields := make([]hpack.HeaderField, 0, 1+len(extra))
	fields = append(fields, hpack.HeaderField{Name: ":status", Value: strconv.Itoa(status)})
	fields = append(fields, extra...)
	frag, err := s.conn.encodeHeaders(fields)
	if err != nil {
		return err
	}
	return s.conn.fw.writeFrame(frameHeaders, flagEndHeaders, s.ID, frag)
}

// WriteData sends body bytes, chunked to the connection's MaxFrameSize.
// endStream marks the final frame and completes the stream.
func (s *Stream) WriteData(p []byte, endStream bool) error {
	max := int(s.conn.cfg.MaxFrameSize)
	wrote := false
	for len(p) > 0 {
		n := min(len(p), max)
		last := len(p) == n
		var flags uint8
		if last && endStream {
			flags = flagEndStream
		}
		s.sentBytes.Add(int64(n))
		if err := s.conn.fw.writeFrame(frameData, flags, s.ID, p[:n]); err != nil {
			return err
		}
		wrote = true
		p = p[n:]
	}
	if endStream && !wrote {
		// Empty body: still need a frame carrying END_STREAM.
		if err := s.conn.fw.writeFrame(frameData, flagEndStream, s.ID, nil); err != nil {
			return err
		}
	}
	if endStream {
		s.conn.streamCompleted(s.ID)
	}
	return nil
}

// WriteResponse is the common case: status, body, end of stream.
func (s *Stream) WriteResponse(status int, body []byte) error {
	if err := s.WriteHead(status); err != nil {
		return err
	}
	return s.WriteData(body, true)
}
