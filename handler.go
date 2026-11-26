package h2

import (
	"context"
	"io"

	"golang.org/x/net/http2/hpack"
)

// Handler processes one fully validated HTTP/2 request stream. The
// implementation runs in its own goroutine and may block; client
// cancellation (RST_STREAM) cancels Request.Context().
type Handler interface {
	ServeHTTP(r *Request, w *Responder)
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(r *Request, w *Responder)

// ServeHTTP implements Handler.
func (f HandlerFunc) ServeHTTP(r *Request, w *Responder) { f(r, w) }

// Request is one admitted, header-validated HTTP/2 request.
type Request struct {
	// StreamID is the client-initiated (odd) stream identifier.
	StreamID  uint32
	Method    string
	Scheme    string
	Authority string
	Path      string
	// Headers holds every decoded field in wire order, including
	// pseudo-headers.
	Headers []hpack.HeaderField

	stream *Stream
}

// Context is cancelled when the client resets the stream or the connection
// closes.
func (r *Request) Context() context.Context { return r.stream.ctx }

// Body returns the request body reader. It returns io.EOF after the
// client's END_STREAM. A RST_STREAM surfaces as ErrStreamReset.
func (r *Request) Body() io.Reader { return r.stream }

// MarkDispatched tells the frame layer that backend work for this request
// has actually started — in a reverse proxy this is the moment the upstream
// connection is established or the first upstream byte is sent. A
// RST_STREAM arriving before this call counts as a phantom
// (cancel-before-work) stream for Rapid Reset accounting; after it, the
// reset is treated as an ordinary client cancellation and cannot by itself
// degrade the connection. Call it exactly once, as early as possible.
func (r *Request) MarkDispatched() { r.stream.MarkDispatched() }

// Header returns the first value for name (case-insensitive), or "".
func (r *Request) Header(name string) string {
	for _, hf := range r.Headers {
		if equalFold(hf.Name, name) {
			return hf.Value
		}
	}
	return ""
}

// ErrStreamReset is returned by request-body reads after RST_STREAM.
var ErrStreamReset = streamError(0, ErrCodeCancel, "stream reset by peer")

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
