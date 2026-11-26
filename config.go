package h2

import "time"

// Config holds the hard limits and adaptive-control thresholds for one
// connection. The zero value is not usable; call DefaultConfig and override
// the fields they care about. All limits are deliberately expressed in
// protocol units (frames, bytes, streams) so they can be audited against the
// RFC one by one.
type Config struct {
	// ---- HTTP/2 settings we advertise to the peer (RFC 9113 §6.5) ----

	// InitialMaxConcurrentStreams is the SETTINGS_MAX_CONCURRENT_STREAMS
	// value sent in the initial SETTINGS frame. The adaptive limiter may
	// lower the effective value at runtime but never raises it above this.
	InitialMaxConcurrentStreams uint32

	// InitialStreamWindow / InitialConnWindow are the flow-control window
	// sizes advertised via SETTINGS_INITIAL_WINDOW_SIZE and the connection
	// window sent in the first WINDOW_UPDATE.
	InitialStreamWindow uint32
	InitialConnWindow   int32

	// MaxFrameSize is SETTINGS_MAX_FRAME_SIZE: the largest payload a peer
	// is allowed to send us (RFC 9113 allows 16384..16777215).
	MaxFrameSize uint32

	// MaxHeaderListSize is SETTINGS_MAX_HEADER_LIST_SIZE, the advertised
	// uncompressed header-list size per stream. This is advisory to the
	// peer; we enforce it unconditionally on decode regardless.
	MaxHeaderListSize uint32

	// ---- Hard caps enforced regardless of peer SETTINGS ----

	// HardMaxDynamicTableSize caps SETTINGS_HEADER_TABLE_SIZE (the table
	// the *peer* uses to encode toward us) and the max size our HPACK
	// decoder will accept in a dynamic-table-size update. The peer cannot
	// negotiate a larger table.
	HardMaxDynamicTableSize uint32

	// MaxHeaderBlockBytes caps the raw, still-compressed bytes of one
	// reassembled header block (HEADERS + CONTINUATION payloads). This is
	// the primary HPACK-bomb guard: no single block may exceed it even if
	// its compressed representation is tiny.
	MaxHeaderBlockBytes uint32

	// MaxContinuationFrames caps how many CONTINUATION frames may follow
	// one HEADERS frame. The CVE-2024-27316 class of attack holds the
	// connection inside an endless CONTINUATION sequence.
	MaxContinuationFrames uint32

	// MaxHeaderFields caps the number of fields in one decoded header list.
	MaxHeaderFields uint32

	// MaxHeaderFieldSize caps the size of a single decoded header name or
	// value (enforced via hpack.Decoder.SetMaxStringLength).
	MaxHeaderFieldSize uint32

	// MaxHPACKInsertsPerBlock caps the number of literal-with-indexing
	// representations (dynamic-table inserts) in one header block.
	MaxHPACKInsertsPerBlock uint32

	// MaxHPACKTableUpdates caps the number of dynamic-table-size updates
	// within one header block. RFC 7541 only permits these at the start of
	// a block, so more than a handful is unambiguously hostile.
	MaxHPACKTableUpdates uint32

	// MaxHPACKInsertsPerConn is the cumulative budget of dynamic-table
	// inserts over the whole connection. A legitimate long-lived player
	// connection reuses the table rather than rebuilding it, so this only
	// trips on churn attacks that keep forcing evictions.
	MaxHPACKInsertsPerConn uint64

	// ---- Rapid Reset adaptive control (per connection) ----

	// StatWindow is the sliding window over which creations/resets are
	// counted.
	StatWindow time.Duration

	// MinSamples is the number of stream-open events inside the window
	// below which the limiter never escalates: small-N ratios are too
	// noisy to act on. This is the main false-positive guard for ordinary
	// browsers.
	MinSamples uint32

	// DegradeResetRatio / CloseResetRatio are the reset/open ratios that
	// move the connection into DEGRADED / CLOSING.
	DegradeResetRatio float64
	CloseResetRatio   float64

	// ShortStreamFraction is the fraction of opens that must be
	// "phantom" streams (RST_STREAM received before the backend request
	// was even dispatched) for ratio-based escalation. A seek burst
	// cancels in-flight requests that already ran; a Rapid Reset client
	// cancels streams that never did any work.
	ShortStreamFraction float64

	// DegradedMaxConcurrentStreams is the effective concurrency cap while
	// DEGRADED.
	DegradedMaxConcurrentStreams uint32

	// Cooldown is the quiet period (no escalation event) after which a
	// DEGRADED connection is promoted back to NORMAL. Hysteresis prevents
	// flapping on the boundary.
	Cooldown time.Duration

	// MaxConcurrentShortStreams is an absolute, ratio-independent cap on
	// the number of phantom streams inside the window. Go's own Rapid
	// Reset mitigation uses the same idea (the "stream cancel" budget).
	MaxConcurrentShortStreams uint32

	// ---- Timeouts ----

	// HeaderTimeout bounds the time between a HEADERS frame and the frame
	// that terminates its block (END_HEADERS). An interrupted CONTINUATION
	// sequence blocks every other stream on the connection, so this must
	// be short.
	HeaderTimeout time.Duration

	// WriteTimeout bounds every frame write.
	WriteTimeout time.Duration

	// GoAwayGrace is how long we keep draining in-flight streams after
	// sending GOAWAY before closing the TCP connection.
	GoAwayGrace time.Duration
}

// DefaultConfig returns limits tuned for a video CDN edge: generous enough
// for seek-happy browsers and long-lived player connections, strict enough to
// make the documented attacks fail closed.
func DefaultConfig() *Config {
	return &Config{
		InitialMaxConcurrentStreams: 250,
		InitialStreamWindow:         1 << 20, // 1 MiB, same order as Go's default
		InitialConnWindow:           1 << 20,
		MaxFrameSize:                16384, // RFC default; peers may ask up to 16MiB
		MaxHeaderListSize:           32 << 10,

		HardMaxDynamicTableSize: 4 << 10, // 4 KiB dynamic table is ample for H2
		MaxHeaderBlockBytes:     64 << 10,
		MaxContinuationFrames:   8,
		MaxHeaderFields:         100,
		MaxHeaderFieldSize:      16 << 10,
		MaxHPACKInsertsPerBlock: 256,
		MaxHPACKTableUpdates:    4,
		// 10k inserts/conn: a normal connection reaches steady state after
		// a few dozen inserts and then only references them.
		MaxHPACKInsertsPerConn: 10000,

		StatWindow:                   10 * time.Second,
		MinSamples:                   50,
		DegradeResetRatio:            0.5,
		CloseResetRatio:              0.8,
		ShortStreamFraction:          0.5,
		DegradedMaxConcurrentStreams: 32,
		Cooldown:                     30 * time.Second,
		// Phantom budget: 200 cancel-before-dispatch streams per window is
		// far above any real UI gesture and far below attack rates
		// (thousands/sec).
		MaxConcurrentShortStreams: 200,

		HeaderTimeout: 10 * time.Second,
		WriteTimeout:  10 * time.Second,
		GoAwayGrace:   5 * time.Second,
	}
}
