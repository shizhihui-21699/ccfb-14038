package h2

import (
	"testing"
	"time"
)

func testLimiterConfig() *Config {
	c := DefaultConfig()
	c.StatWindow = 200 * time.Millisecond
	c.MinSamples = 50
	c.DegradeResetRatio = 0.5
	c.CloseResetRatio = 0.8
	c.ShortStreamFraction = 0.5
	c.MaxConcurrentShortStreams = 100
	c.DegradedMaxConcurrentStreams = 8
	c.InitialMaxConcurrentStreams = 64
	c.Cooldown = 150 * time.Millisecond
	return c
}

// A browser seek burst: many cancellations, but the cancelled streams had
// already been dispatched (non-phantom). The limiter must not escalate even
// when the raw reset ratio is very high — this is the headline false
// positive the design exists to prevent.
func TestLimiterSeekBurstIsNotRapidReset(t *testing.T) {
	l := NewAdaptiveLimiter(testLimiterConfig())

	for i := 0; i < 200; i++ {
		if ev := l.RecordOpen(); ev != EventNone {
			t.Fatalf("unexpected escalation at open %d: %v", i, ev)
		}
		// Simulate dispatch happening before the client gives up.
		// RecordReset(phantom=false) is a seek cancel of real work.
		if ev := l.RecordReset(false); ev != EventNone {
			t.Fatalf("seek burst escalated at reset %d: %v (stats=%+v)", i, ev, l.Stats())
		}
	}
	if got := l.State(); got != StateNormal {
		t.Fatalf("seek burst moved state to %v, want NORMAL; stats=%+v", got, l.Stats())
	}
}

// Below MinSamples, a 100% reset ratio is statistically meaningless and
// must be ignored: tiny burst cancellations happen in normal browsing
// (double-click, redirected media URLs).
func TestLimiterIgnoresSmallSamples(t *testing.T) {
	l := NewAdaptiveLimiter(testLimiterConfig())
	for i := 0; i < 40; i++ { // under MinSamples=50
		l.RecordOpen()
		if ev := l.RecordReset(true); ev != EventNone {
			t.Fatalf("small-sample phantom burst escalated: %v", ev)
		}
	}
	if l.State() != StateNormal {
		t.Fatalf("state=%v, want NORMAL", l.State())
	}
}

// The actual attack: phantom streams (cancel before dispatch). Phase 1
// mixes enough healthy opens to stop at DEGRADED; phase 2 turns fully
// phantom and must reach CLOSING. This exercises both transitions.
func TestLimiterRapidResetEscalates(t *testing.T) {
	c := testLimiterConfig()
	c.DegradeResetRatio = 0.5
	c.CloseResetRatio = 0.9
	c.MinSamples = 20
	l := NewAdaptiveLimiter(c)

	// Phase 1: 100 opens, 60 phantom resets -> ratio 0.6, phantom 0.6:
	// above degrade (0.5), below close (0.9).
	degradedAt := -1
	for i := 0; i < 100; i++ {
		if ev := l.RecordOpen(); ev == EventDegraded && degradedAt < 0 {
			degradedAt = i
		}
		if i%10 < 6 {
			if ev := l.RecordReset(true); ev == EventClosing {
				t.Fatalf("closed during degrade phase at %d: %+v", i, l.Stats())
			}
		}
	}
	if degradedAt < 0 || l.State() != StateDegraded {
		t.Fatalf("phase1: state=%v degradedAt=%d stats=%+v", l.State(), degradedAt, l.Stats())
	}

	// Phase 2: pure phantom cycles push the window ratio past 0.9.
	closingAt := -1
	for i := 0; i < 400; i++ {
		l.RecordOpen()
		if ev := l.RecordReset(true); ev == EventClosing {
			closingAt = i
			break
		}
	}
	if closingAt < 0 {
		t.Fatalf("phase2 never closed; stats=%+v", l.Stats())
	}
	if l.State() != StateClosing {
		t.Fatalf("final state=%v, want CLOSING", l.State())
	}
}

// The phantom absolute cap trips regardless of ratio math: an attacker
// pacing just under the ratio threshold still cannot exceed the hard
// phantom budget inside a window.
func TestLimiterPhantomAbsoluteCap(t *testing.T) {
	c := testLimiterConfig()
	c.MaxConcurrentShortStreams = 60
	c.MinSamples = 1000 // make the ratio path unreachable in this test
	l := NewAdaptiveLimiter(c)

	events := 0
	for i := 0; i < 120; i++ {
		l.RecordOpen()
		// Half the streams phantom, half normal: ratio stays modest.
		phantom := i%2 == 0
		if ev := l.RecordReset(phantom); ev != EventNone {
			events++
		}
	}
	if l.State() != StateClosing {
		t.Fatalf("absolute phantom cap did not trip; state=%v stats=%+v", l.State(), l.Stats())
	}
	if events == 0 {
		t.Fatal("no escalation event delivered")
	}
}

// After degradation, a quiet connection recovers to NORMAL once the cooldown
// elapses and the window has aged out the bad samples (hysteresis).
func TestLimiterRecoversAfterCooldown(t *testing.T) {
	c := testLimiterConfig()
	c.DegradeResetRatio = 0.5
	c.CloseResetRatio = 0.9
	c.MinSamples = 20
	l := NewAdaptiveLimiter(c)

	// 100 opens, 60 phantom resets: ratio 0.6 -> DEGRADED only.
	for i := 0; i < 100; i++ {
		l.RecordOpen()
		if i%10 < 6 {
			l.RecordReset(true)
		}
	}
	if l.State() != StateDegraded {
		t.Fatalf("setup: state=%v stats=%+v", l.State(), l.Stats())
	}

	// Wait long enough for both the stat window and cooldown to pass.
	time.Sleep(c.StatWindow + c.Cooldown + 50*time.Millisecond)
	// A fresh, healthy open/close pair triggers re-evaluation.
	if ev := l.RecordOpen(); ev != EventNone {
		t.Fatalf("recovery open escalated: %v", ev)
	}
	if got := l.State(); got != StateNormal {
		t.Fatalf("state after cooldown=%v, want NORMAL", got)
	}
}

// TryAcquire enforces the degraded cap and releases are balanced.
func TestLimiterSemaphoreCaps(t *testing.T) {
	c := testLimiterConfig()
	l := NewAdaptiveLimiter(c)

	for i := 0; i < int(c.InitialMaxConcurrentStreams); i++ {
		if !l.TryAcquire() {
			t.Fatalf("acquire %d failed under normal cap", i)
		}
	}
	if l.TryAcquire() {
		t.Fatal("acquisition past normal cap succeeded")
	}
	for i := 0; i < int(c.InitialMaxConcurrentStreams); i++ {
		l.Release()
	}
	if got := l.InFlight(); got != 0 {
		t.Fatalf("InFlight after releases=%d, want 0", got)
	}

	// Force degraded state, then the effective cap must shrink.
	l.mu.Lock()
	l.state = StateDegraded
	l.mu.Unlock()
	for i := 0; i < int(c.DegradedMaxConcurrentStreams); i++ {
		if !l.TryAcquire() {
			t.Fatalf("degraded acquire %d failed", i)
		}
	}
	if l.TryAcquire() {
		t.Fatal("acquisition past degraded cap succeeded")
	}
	if l.EffectiveLimit() != c.DegradedMaxConcurrentStreams {
		t.Fatalf("EffectiveLimit=%d, want %d", l.EffectiveLimit(), c.DegradedMaxConcurrentStreams)
	}
}

// A long-lived player connection steadily opening streams with few resets
// must stay NORMAL indefinitely — the window slides, it does not accumulate
// over the connection lifetime.
func TestLimiterSteadyPlayerTraffic(t *testing.T) {
	c := testLimiterConfig()
	l := NewAdaptiveLimiter(c)
	deadline := time.Now().Add(c.StatWindow * 6)
	for time.Now().Before(deadline) {
		for i := 0; i < 10; i++ {
			if ev := l.RecordOpen(); ev != EventNone {
				t.Fatalf("steady traffic escalated: %v stats=%+v", ev, l.Stats())
			}
		}
		// Occasional, non-phantom cancel (user pauses a segment load).
		l.RecordReset(false)
		time.Sleep(c.StatWindow / 4)
	}
	if l.State() != StateNormal {
		t.Fatalf("steady player traffic ended in state=%v stats=%+v", l.State(), l.Stats())
	}
}
