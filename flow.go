package h2

import (
	"context"
	"sync"
)

// maxWindow is the 2^31-1 ceiling on every HTTP/2 flow-control window.
const maxWindow = 1<<31 - 1

// outWindow is a flow-control window for data WE send (responses). Writes
// wait for credit the peer hands back via WINDOW_UPDATE; stream or
// connection cancellation unblocks every waiter.
type outWindow struct {
	mu     sync.Mutex
	cond   *sync.Cond
	credit int32
	closed bool
	err    error
}

func newOutWindow(initial int32) *outWindow {
	w := &outWindow{credit: initial}
	w.cond = sync.NewCond(&w.mu)
	return w
}

// Wait blocks until at least n bytes of credit are available, then reserves
// them. It honors ctx so a client RST_STREAM unblocks handler writes. The
// wait is a cond loop that re-checks ctx after every wakeup; Close() on the
// window (reset/GOAWAY) guarantees every waiter is woken even without ctx.
func (w *outWindow) Wait(ctx context.Context, n int32) error {
	if n <= 0 {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for {
		if w.closed {
			return w.err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if w.credit >= n {
			w.credit -= n
			return nil
		}
		w.cond.Wait()
	}
}

// Add credits a WINDOW_UPDATE. An overflow beyond 2^31-1 is reported as an
// error so the caller can answer FLOW_CONTROL_ERROR (RFC 9113 §6.9.1).
func (w *outWindow) Add(n int32) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if n <= 0 {
		return connError(ErrCodeFlowControl, "WINDOW_UPDATE increment must be between 1 and 2^31-1")
	}
	if int64(w.credit)+int64(n) > maxWindow {
		return connError(ErrCodeFlowControl, "flow-control window overflow")
	}
	w.credit += n
	w.cond.Broadcast()
	return nil
}

// SetInitial adjusts the window for a SETTINGS_INITIAL_WINDOW_SIZE change.
// RFC 9113 §6.9.2: the delta is applied to every stream; negative deltas
// may leave the window negative and writers then wait for enough updates.
func (w *outWindow) SetInitial(old, new uint32) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.credit += int32(new) - int32(old)
	w.cond.Broadcast()
}

// Close unblocks all waiters with err.
func (w *outWindow) Close(err error) {
	w.mu.Lock()
	w.closed = true
	w.err = err
	w.cond.Broadcast()
	w.mu.Unlock()
}

// inWindow is a flow-control window for data the PEER sends us (requests).
// DATA frames consume credit synchronously in the read loop (never blocks);
// handler reads return credit with WINDOW_UPDATE.
type inWindow struct {
	mu     sync.Mutex
	credit int32
}

func newInWindow(initial int32) *inWindow { return &inWindow{credit: initial} }

// Take reserves credit for an inbound DATA payload. A negative result is a
// protocol violation: the peer sent more data than its window allowed.
func (w *inWindow) Take(n int32) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if int64(w.credit)-int64(n) < 0 {
		return connError(ErrCodeFlowControl, "peer exceeded flow-control window")
	}
	w.credit -= n
	return nil
}

// giveBack returns previously consumed credit to the window after the
// application drained buffered DATA and a WINDOW_UPDATE was emitted. A
// result above 2^31-1 cannot happen for correctly matched take/refund pairs
// but is clamped defensively.
func (w *inWindow) giveBack(n int32) {
	w.mu.Lock()
	w.credit += n
	if w.credit > maxWindow {
		w.credit = maxWindow
	}
	w.mu.Unlock()
}

// Credit reports remaining inbound credit (for tests/diagnostics).
func (w *inWindow) Credit() int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.credit
}
