package h2guard

import (
	"math"
	"time"
)

// decayCounter counts events with exponential decay, giving a sliding
// window rate without storing per-event timestamps. With half-life T, a
// sustained event rate r settles at roughly r * T / ln(2).
type decayCounter struct {
	halfLife float64 // seconds
	value    float64
	last     time.Time
}

func newDecayCounter(halfLife time.Duration) decayCounter {
	return decayCounter{halfLife: halfLife.Seconds()}
}

func (c *decayCounter) decay(now time.Time) {
	if c.last.IsZero() {
		c.last = now
		return
	}
	dt := now.Sub(c.last).Seconds()
	if dt <= 0 {
		return
	}
	c.value *= math.Pow(0.5, dt/c.halfLife)
	c.last = now
}

// Add registers n events and returns the decayed total.
func (c *decayCounter) Add(n float64, now time.Time) float64 {
	c.decay(now)
	c.value += n
	return c.value
}

// Value returns the decayed total without registering an event.
func (c *decayCounter) Value(now time.Time) float64 {
	c.decay(now)
	return c.value
}

// connStats tracks what a connection is doing, split the way the attack
// surface splits:
//
//   - earlyReset: RST_STREAM before any response byte was sent. This is
//     the CVE-2023-44487 "rapid reset" shape. Legit clients rarely do
//     this (an aborted preconnect, a cancelled prefetch), attackers do it
//     thousands of times per second.
//   - lateReset: RST_STREAM after response bytes flowed. This is the
//     browser seek / pause shape — completely normal on a video site —
//     so it is counted for observability but never punished.
//   - completed: streams that finished normally. These earn budget back.
type connStats struct {
	opened     decayCounter
	earlyReset decayCounter
	lateReset  decayCounter
	completed  decayCounter
}

func newConnStats() connStats {
	const halfLife = 10 * time.Second
	return connStats{
		opened:     newDecayCounter(halfLife),
		earlyReset: newDecayCounter(halfLife),
		lateReset:  newDecayCounter(halfLife),
		completed:  newDecayCounter(halfLife),
	}
}

// degradeAction tells the connection what to do after an event.
type degradeAction int

const (
	actionNone   degradeAction = iota // nothing changed
	actionDegrade                     // concurrency limit changed; re-advertise SETTINGS
	actionGoAway                      // budget exhausted at the last level; tear the conn down
)

// degradeConfig tunes degradeController.
type degradeConfig struct {
	// levels lists the MaxConcurrentStreams values the connection is
	// stepped through, most generous first. Exhausting the budget at the
	// last level triggers GOAWAY.
	levels []uint32
	// budgetCap is the token-bucket capacity for early resets.
	budgetCap float64
	// refillPerSec is the passive budget refill rate.
	refillPerSec float64
	// completedCredit is the budget regained per completed stream.
	completedCredit float64
	// recoverAfter is how long the connection must stay clean (no early
	// resets) before stepping back up one level.
	recoverAfter time.Duration
}

// degradeController implements the punishment ladder for rapid-reset
// shaped traffic. The key asymmetry: a normal viewer costs the bucket
// almost nothing (seeks are late resets, completed streams refund
// budget), while a rapid-reset attack spends it hundreds of times per
// second, so even a generous bucket separates them cleanly.
type degradeController struct {
	cfg          degradeConfig
	level        int
	budget       float64
	lastEvent    time.Time
	lastEarlyRst time.Time
}

func newDegradeController(cfg degradeConfig) *degradeController {
	return &degradeController{cfg: cfg, budget: cfg.budgetCap}
}

func (d *degradeController) maxConcurrent() uint32 {
	return d.cfg.levels[d.level]
}

func (d *degradeController) refill(now time.Time) {
	if d.lastEvent.IsZero() {
		d.lastEvent = now
		return
	}
	dt := now.Sub(d.lastEvent).Seconds()
	d.lastEvent = now
	if dt <= 0 {
		return
	}
	d.budget = math.Min(d.cfg.budgetCap, d.budget+dt*d.cfg.refillPerSec)
}

// onEarlyReset spends one unit of budget.
func (d *degradeController) onEarlyReset(now time.Time) degradeAction {
	d.refill(now)
	d.lastEarlyRst = now
	d.budget--
	if d.budget >= 0 {
		return actionNone
	}
	d.level++
	if d.level >= len(d.cfg.levels) {
		d.level = len(d.cfg.levels) - 1
		return actionGoAway
	}
	// Half a budget at the new, stricter level: if the burst continues
	// it pushes us to the next level quickly; if it stops, recovery
	// starts counting.
	d.budget = d.cfg.budgetCap / 2
	return actionDegrade
}

// onCompleted earns budget back for a normally-completed stream.
func (d *degradeController) onCompleted(now time.Time) {
	d.refill(now)
	d.budget = math.Min(d.cfg.budgetCap, d.budget+d.cfg.completedCredit)
}

// tick implements recovery: a connection that stays clean for
// recoverAfter steps back up one level. Call it once per read-loop
// iteration.
func (d *degradeController) tick(now time.Time) degradeAction {
	if d.level == 0 || d.lastEarlyRst.IsZero() {
		return actionNone
	}
	if now.Sub(d.lastEarlyRst) < d.cfg.recoverAfter {
		return actionNone
	}
	d.level--
	d.lastEarlyRst = time.Time{}
	d.budget = d.cfg.budgetCap / 2
	return actionDegrade
}
