package h2

import (
	"sync"
	"time"
)

// LimiterState is the adaptive trust level of one connection.
type LimiterState uint8

const (
	// StateNormal: full configured concurrency, accounting only.
	StateNormal LimiterState = iota
	// StateDegraded: concurrency pinned to DegradedMaxConcurrentStreams;
	// the connection keeps serving in-flight and new streams under the
	// reduced cap. Recovery is possible after Cooldown.
	StateDegraded
	// StateClosing: no new streams are admitted; Conn sends GOAWAY with
	// ENHANCE_YOUR_CALM and drains in-flight streams.
	StateClosing
)

func (s LimiterState) String() string {
	switch s {
	case StateNormal:
		return "NORMAL"
	case StateDegraded:
		return "DEGRADED"
	default:
		return "CLOSING"
	}
}

// LimiterEvent is returned from every accounting call so the Conn read loop
// can react to a state transition exactly once.
type LimiterEvent uint8

const (
	EventNone LimiterEvent = iota
	EventDegraded
	EventClosing
)

// bucket holds one time slice of the sliding window.
type bucket struct {
	slot    int64 // window slot index (Truncate(bucketLen)); -1 = unused
	opens   uint32
	resets  uint32
	phantom uint32 // resets that arrived before backend dispatch
}

// AdaptiveLimiter keeps per-connection Rapid Reset accounting in a sliding
// window and maps the numbers onto a three-state controller. All methods
// are safe for concurrent use; the hot path (Record*/Acquire) takes one
// uncontended mutex and does no allocation.
type AdaptiveLimiter struct {
	cfg *Config

	mu sync.Mutex

	state   LimiterState
	semUsed uint32 // currently admitted streams

	ring      []bucket
	head      int // index of the newest slot in ring
	bucketLen time.Duration
	lastBadAt time.Time

	// window totals of the current ring, maintained incrementally so an
	// escalation decision never scans the ring under load.
	wOpens   uint32
	wResets  uint32
	wPhantom uint32
}

// NewAdaptiveLimiter builds a limiter with StatWindow split into 10 equal
// buckets.
func NewAdaptiveLimiter(cfg *Config) *AdaptiveLimiter {
	const nBuckets = 10
	l := &AdaptiveLimiter{
		cfg:       cfg,
		ring:      make([]bucket, nBuckets),
		head:      0,
		bucketLen: cfg.StatWindow / nBuckets,
	}
	for i := range l.ring {
		l.ring[i].slot = -1
	}
	return l
}

// State returns the current trust level.
func (l *AdaptiveLimiter) State() LimiterState {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.state
}

// EffectiveLimit is the concurrency cap right now.
func (l *AdaptiveLimiter) EffectiveLimit() uint32 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.effectiveLimitLocked()
}

func (l *AdaptiveLimiter) effectiveLimitLocked() uint32 {
	if l.state == StateDegraded || l.state == StateClosing {
		return l.cfg.DegradedMaxConcurrentStreams
	}
	return l.cfg.InitialMaxConcurrentStreams
}

// current returns a pointer to the bucket for now, aging out every slot
// that fell outside the window. Caller holds l.mu.
func (l *AdaptiveLimiter) current(now time.Time) *bucket {
	slot := now.Truncate(l.bucketLen).UnixNano() / int64(l.bucketLen)
	cur := &l.ring[l.head]
	if cur.slot == slot {
		return cur
	}
	if cur.slot == -1 {
		cur.slot = slot
		return cur
	}
	steps := slot - cur.slot
	n := int64(len(l.ring))
	if steps >= n {
		// Idle longer than the whole window: all old data is stale.
		for i := range l.ring {
			l.ring[i] = bucket{slot: -1}
		}
		l.wOpens, l.wResets, l.wPhantom = 0, 0, 0
		l.ring[l.head].slot = slot
		return &l.ring[l.head]
	}
	// Advance the head, clearing each reused slot and subtracting it from
	// the window totals.
	for i := int64(0); i < steps; i++ {
		l.head = (l.head + 1) % len(l.ring)
		old := l.ring[l.head]
		l.wOpens -= old.opens
		l.wResets -= old.resets
		l.wPhantom -= old.phantom
		l.ring[l.head] = bucket{slot: cur.slot + i + 1}
	}
	return &l.ring[l.head]
}

// RecordOpen accounts a newly created stream (HEADERS on an unused ID).
func (l *AdaptiveLimiter) RecordOpen() LimiterEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b := l.current(now)
	b.opens++
	l.wOpens++
	return l.evaluateLocked(now)
}

// RecordReset accounts a client-initiated RST_STREAM. phantom must be true
// when the stream had not yet been dispatched to a backend (no work was
// done); seek cancellations of real in-flight requests pass false.
func (l *AdaptiveLimiter) RecordReset(phantom bool) LimiterEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b := l.current(now)
	b.resets++
	l.wResets++
	if phantom {
		b.phantom++
		l.wPhantom++
	}
	return l.evaluateLocked(now)
}

// evaluateLocked runs the escalation/recovery rules. Caller holds l.mu.
//
// The two-stage guard against false positives:
//  1. MinSamples: ignore ratios while the window holds fewer than this
//     many opens — a browser seeking through a video produces bursts but
//     also plenty of ordinary traffic, whereas early-window ratios of 2/3
//     are statistically meaningless.
//  2. ShortStreamFraction: ratio escalation also requires that at least
//     this fraction of opens were phantom (cancel-before-dispatch). Real
//     seek storms cancel work that actually ran, so they fail this test
//     even with a high reset ratio.
//
// The phantom *absolute* cap (MaxConcurrentShortStreams) bypasses both
// guards: no legitimate UI gesture creates hundreds of no-work streams.
func (l *AdaptiveLimiter) evaluateLocked(now time.Time) LimiterEvent {
	if l.state == StateClosing {
		return EventNone // terminal for the connection's lifetime
	}

	// Recovery first: a DEGRADED connection that has stayed quiet for the
	// cooldown returns to NORMAL. Hysteresis keeps it from oscillating
	// around a threshold.
	if l.state == StateDegraded && now.Sub(l.lastBadAt) >= l.cfg.Cooldown {
		l.state = StateNormal
		return EventNone
	}

	ratio := 0.0
	if l.wOpens > 0 {
		ratio = float64(l.wResets) / float64(l.wOpens)
	}
	phantomFraction := 0.0
	if l.wOpens > 0 {
		phantomFraction = float64(l.wPhantom) / float64(l.wOpens)
	}

	enoughSamples := l.wOpens >= l.cfg.MinSamples
	ratioGuarded := enoughSamples && phantomFraction >= l.cfg.ShortStreamFraction
	phantomCapTripped := l.wPhantom >= l.cfg.MaxConcurrentShortStreams

	escalate := false
	switch {
	case phantomCapTripped:
		escalate = true
	case ratioGuarded && ratio >= l.cfg.CloseResetRatio:
		escalate = true
	case ratioGuarded && ratio >= l.cfg.DegradeResetRatio && l.state == StateNormal:
		escalate = true
	}
	if !escalate {
		return EventNone
	}

	l.lastBadAt = now
	if phantomCapTripped || (ratioGuarded && ratio >= l.cfg.CloseResetRatio) {
		l.state = StateClosing
		return EventClosing
	}
	l.state = StateDegraded
	return EventDegraded
}

// TryAcquire reserves one stream concurrency slot. It never blocks: when no
// slot is available the caller answers REFUSED_STREAM (RFC 9113 §8.14),
// which browsers treat as retryable rather than as a broken connection.
func (l *AdaptiveLimiter) TryAcquire() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state == StateClosing {
		return false
	}
	if l.semUsed >= l.effectiveLimitLocked() {
		return false
	}
	l.semUsed++
	return true
}

// Release returns a slot acquired with TryAcquire. Idempotency across the
// various stream-end paths is provided by Conn.releaseSlot, which guards a
// per-stream flag; this method assumes one matching call per acquisition.
func (l *AdaptiveLimiter) Release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.semUsed > 0 {
		l.semUsed--
	}
}

// InFlight returns how many slots are currently held.
func (l *AdaptiveLimiter) InFlight() uint32 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.semUsed
}

// Snapshot is a point-in-time view of the window counters, for logging and
// tests.
type Snapshot struct {
	State        LimiterState
	Opens        uint32
	Resets       uint32
	Phantom      uint32
	InFlight     uint32
	EffectiveCap uint32
	ResetRatio   float64
	PhantomRatio float64
}

// Stats returns the current Snapshot.
func (l *AdaptiveLimiter) Stats() Snapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := Snapshot{
		State:        l.state,
		Opens:        l.wOpens,
		Resets:       l.wResets,
		Phantom:      l.wPhantom,
		InFlight:     l.semUsed,
		EffectiveCap: l.effectiveLimitLocked(),
	}
	if l.wOpens > 0 {
		s.ResetRatio = float64(l.wResets) / float64(l.wOpens)
		s.PhantomRatio = float64(l.wPhantom) / float64(l.wOpens)
	}
	return s
}
