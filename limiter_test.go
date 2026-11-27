package h2guard

import (
	"math"
	"testing"
	"time"
)

func TestDecayCounter(t *testing.T) {
	c := newDecayCounter(10 * time.Second)
	t0 := time.Unix(1000, 0)
	c.Add(8, t0)
	if got := c.Value(t0); got != 8 {
		t.Fatalf("value = %v, want 8", got)
	}
	// One half-life later the count should have halved.
	if got := c.Value(t0.Add(10 * time.Second)); math.Abs(got-4) > 1e-9 {
		t.Fatalf("value after half-life = %v, want 4", got)
	}
	// And the decay applies to newly added events too.
	if got := c.Add(4, t0.Add(20*time.Second)); math.Abs(got-6) > 1e-9 {
		t.Fatalf("value after add = %v, want 6", got)
	}
}

func TestDegradeControllerLadder(t *testing.T) {
	d := newDegradeController(degradeConfig{
		levels:          []uint32{100, 10, 1},
		budgetCap:       4,
		refillPerSec:    0,
		completedCredit: 1,
		recoverAfter:    30 * time.Second,
	})
	t0 := time.Unix(1000, 0)

	if got := d.maxConcurrent(); got != 100 {
		t.Fatalf("initial maxConcurrent = %d, want 100", got)
	}
	// Spend the budget: 4 early resets fit, the 5th degrades.
	for i := 0; i < 4; i++ {
		if a := d.onEarlyReset(t0); a != actionNone {
			t.Fatalf("reset %d: action = %v, want none", i+1, a)
		}
	}
	if a := d.onEarlyReset(t0); a != actionDegrade {
		t.Fatalf("5th reset: action = %v, want degrade", a)
	}
	if got := d.maxConcurrent(); got != 10 {
		t.Fatalf("maxConcurrent = %d, want 10", got)
	}
	// Half budget (2) at the new level: 3rd reset here degrades again.
	d.onEarlyReset(t0)
	d.onEarlyReset(t0)
	if a := d.onEarlyReset(t0); a != actionDegrade {
		t.Fatalf("action = %v, want degrade", a)
	}
	if got := d.maxConcurrent(); got != 1 {
		t.Fatalf("maxConcurrent = %d, want 1", got)
	}
	// Exhaust the last level -> GOAWAY.
	d.onEarlyReset(t0)
	d.onEarlyReset(t0)
	if a := d.onEarlyReset(t0); a != actionGoAway {
		t.Fatalf("action = %v, want goaway", a)
	}
}

func TestDegradeControllerRecovery(t *testing.T) {
	d := newDegradeController(degradeConfig{
		levels:          []uint32{100, 10, 1},
		budgetCap:       4,
		refillPerSec:    0,
		completedCredit: 1,
		recoverAfter:    30 * time.Second,
	})
	t0 := time.Unix(1000, 0)
	for i := 0; i < 5; i++ {
		d.onEarlyReset(t0)
	}
	if d.level != 1 {
		t.Fatalf("level = %d, want 1", d.level)
	}
	// Clean traffic for the recovery window steps back up.
	if a := d.tick(t0.Add(31 * time.Second)); a != actionDegrade {
		t.Fatalf("tick action = %v, want degrade (recovery)", a)
	}
	if d.level != 0 || d.maxConcurrent() != 100 {
		t.Fatalf("level = %d, want 0", d.level)
	}
}

func TestDegradeControllerCompletedCredit(t *testing.T) {
	d := newDegradeController(degradeConfig{
		levels:          []uint32{100, 10},
		budgetCap:       4,
		refillPerSec:    0,
		completedCredit: 1,
		recoverAfter:    30 * time.Second,
	})
	t0 := time.Unix(1000, 0)
	// Interleave resets with completions: budget never runs dry.
	for i := 0; i < 50; i++ {
		d.onEarlyReset(t0)
		d.onCompleted(t0)
	}
	if d.level != 0 {
		t.Fatalf("level = %d, want 0 (completions should offset resets)", d.level)
	}
}
