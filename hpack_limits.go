package h2

import (
	"errors"
	"fmt"

	"golang.org/x/net/http2/hpack"
)

// errTruncated means the pre-scanner ran off the end of a block; the block
// was reassembled by our own framer so this is a malformed encoding, not a
// short read, and maps to COMPRESSION_ERROR at the caller.
var errTruncated = errors.New("h2: truncated HPACK block")

// hpackAccount tallies the resource cost of one HPACK block *before* the
// stateful decoder runs. The pre-scan is representation-only (no Huffman
// expansion, no table mutation), so its cost is linear in the wire bytes
// and it cannot be forced into expensive work by the peer.
type hpackAccount struct {
	inserts      uint32 // literal-with-indexing representations (RFC 7541 §6.3)
	tableUpdates uint32 // dynamic-table-size updates (§6.3)
	fields       uint32 // header fields of every kind
	rawLen       uint32 // sum of the reassembled block's wire bytes
}

// ErrHPACKBudget marks a block that passed syntax checks but exceeded one of
// our hard resource budgets. It maps to ENHANCE_YOUR_CALM, never to
// COMPRESSION_ERROR: the encoding is valid, the client is simply spending
// too much.
var ErrHPACKBudget = errors.New("h2: header block exceeded resource budget")

// scanHPACK walks one complete HPACK block counting dynamic-table
// operations. It deliberately does not resolve indexed header fields against
// any table — syntax validity and accounting do not need it — and does not
// decode strings, only measures their wire lengths.
//
// Representation grammar (RFC 7541):
//
//	1xxxxxxx                          indexed header field (§6.1)
//	01xxxxxx                          literal with incremental indexing (§6.2.1)
//	0000xxxx                          literal without indexing (§6.2.2)
//	0001xxxx                          literal never indexed (§6.2.3)
//	001xxxxx                          dynamic table size update (§6.3)
func scanHPACK(block []byte) (hpackAccount, error) {
	var ac hpackAccount
	ac.rawLen = uint32(len(block))
	p := block
	for len(p) > 0 {
		b := p[0]
		switch {
		case b&0x80 != 0:
			// Indexed header field (1xxxxxxx): one varint, nothing else.
			idx, rest, err := readHPACKVarInt(7, p)
			if err != nil {
				return ac, err
			}
			if idx == 0 {
				return ac, hpack.DecodingError{Err: errors.New("indexed header field with index 0")}
			}
			p = rest
			ac.fields++
		case b&0xc0 == 0x40:
			// Literal with incremental indexing (01xxxxxx) => insert.
			rest, err := skipLiteral(6, p)
			if err != nil {
				return ac, err
			}
			p = rest
			ac.inserts++
			ac.fields++
		case b&0xe0 == 0x20:
			// Dynamic table size update (001xxxxx): 5-bit varint, only
			// legal at the start of the block; the hpack.Decoder enforces
			// placement, we only count.
			_, rest, err := readHPACKVarInt(5, p)
			if err != nil {
				return ac, err
			}
			p = rest
			ac.tableUpdates++
		case b&0xf0 == 0x00:
			// Literal without indexing (0000xxxx).
			rest, err := skipLiteral(4, p)
			if err != nil {
				return ac, err
			}
			p = rest
			ac.fields++
		case b&0xf0 == 0x10:
			// Literal never indexed (0001xxxx).
			rest, err := skipLiteral(4, p)
			if err != nil {
				return ac, err
			}
			p = rest
			ac.fields++
		default:
			// Unreachable: the five prefix ranges above partition the
			// whole byte space. Kept as a defensive guard.
			return ac, hpack.DecodingError{Err: fmt.Errorf("illegal HPACK representation prefix 0x%02x", b)}
		}
	}
	return ac, nil
}

// skipLiteral consumes a literal header field representation: index varint
// plus an optional name string and a mandatory value string.
func skipLiteral(prefixBits byte, p []byte) ([]byte, error) {
	idx, rest, err := readHPACKVarInt(prefixBits, p)
	if err != nil {
		return nil, err
	}
	if idx == 0 {
		// New name: name string follows.
		rest, err = skipString(rest)
		if err != nil {
			return nil, err
		}
	}
	rest, err = skipString(rest)
	if err != nil {
		return nil, err
	}
	return rest, nil
}

// skipString consumes one HPACK string literal: 1-bit H flag + 7-bit prefix
// varint length, followed by that many bytes (Huffman-decoded or not does
// not matter for skipping).
func skipString(p []byte) ([]byte, error) {
	if len(p) == 0 {
		return nil, errTruncated
	}
	n, rest, err := readHPACKVarInt(7, p)
	if err != nil {
		return nil, err
	}
	if uint64(len(rest)) < n {
		return nil, errTruncated
	}
	return rest[n:], nil
}

// readHPACKVarInt is a local implementation of RFC 7541 §5.1 so the scanner
// has no dependency on hpack package internals.
func readHPACKVarInt(prefixBits byte, p []byte) (uint64, []byte, error) {
	if len(p) == 0 {
		return 0, nil, errTruncated
	}
	mask := uint64(1<<prefixBits) - 1
	v := uint64(p[0]) & mask
	if v < mask {
		return v, p[1:], nil
	}
	rest := p[1:]
	var shift uint
	for {
		if len(rest) == 0 {
			return 0, nil, errTruncated
		}
		b := rest[0]
		rest = rest[1:]
		// HPACK integers are at most 2^32-1 in practice; guard the shift.
		if shift >= 64 {
			return 0, nil, hpack.DecodingError{Err: errors.New("HPACK integer overflow")}
		}
		v += uint64(b&0x7f) << shift
		shift += 7
		if b&0x80 == 0 {
			return v, rest, nil
		}
	}
}

// BoundedDecoder wraps hpack.Decoder with the connection-wide hard caps.
// One BoundedDecoder is owned by one Conn and used serially from the read
// loop, matching the stateful nature of HPACK dynamic tables.
type BoundedDecoder struct {
	cfg         *Config
	dec         *hpack.Decoder
	connInserts uint64

	// per-block accumulators, reset by BeginBlock
	blockFields uint32
	listSize    uint64 // running uncompressed size per RFC 7541 §4.1
	blockDone   bool
}

// NewBoundedDecoder constructs the decoder with the hard dynamic-table cap
// already armed, so a size update beyond it fails inside hpack as a
// DecodingError (COMPRESSION_ERROR) before any allocation grows.
func NewBoundedDecoder(cfg *Config) *BoundedDecoder {
	bd := &BoundedDecoder{cfg: cfg}
	bd.dec = hpack.NewDecoder(cfg.HardMaxDynamicTableSize, bd.emit)
	bd.dec.SetAllowedMaxDynamicTableSize(cfg.HardMaxDynamicTableSize)
	bd.dec.SetMaxStringLength(int(cfg.MaxHeaderFieldSize))
	return bd
}

func (bd *BoundedDecoder) emit(f hpack.HeaderField) {
	bd.blockFields++
	bd.listSize += uint64(f.Size())
	// Past the list-size budget, stop emitting (and thus allocating
	// strings): the decoder still parses to stay in sync with the table
	// state machine.
	if bd.listSize > uint64(bd.cfg.MaxHeaderListSize) ||
		bd.blockFields > bd.cfg.MaxHeaderFields {
		bd.dec.SetEmitEnabled(false)
	}
}

// BeginBlock resets per-block counters before a HEADERS + CONTINUATION
// sequence is decoded.
func (bd *BoundedDecoder) BeginBlock() {
	bd.blockFields = 0
	bd.listSize = 0
	bd.blockDone = false
	bd.dec.SetEmitEnabled(true)
}

// CheckBlock runs the pre-scan budgets against a fully reassembled block.
// Returning *hpack.DecodingError means a syntax violation (caller maps to
// COMPRESSION_ERROR); ErrHPACKBudget means a resource cap (caller maps to
// ENHANCE_YOUR_CALM).
func (bd *BoundedDecoder) CheckBlock(block []byte) error {
	ac, err := scanHPACK(block)
	if err != nil {
		return err // hpack.DecodingError / ErrNeedMore (truncated => DecodingError path)
	}
	if ac.rawLen > bd.cfg.MaxHeaderBlockBytes {
		return fmt.Errorf("%w: raw header block %d bytes > %d",
			ErrHPACKBudget, ac.rawLen, bd.cfg.MaxHeaderBlockBytes)
	}
	if ac.inserts > bd.cfg.MaxHPACKInsertsPerBlock {
		return fmt.Errorf("%w: %d dynamic-table inserts in one block > %d",
			ErrHPACKBudget, ac.inserts, bd.cfg.MaxHPACKInsertsPerBlock)
	}
	if ac.tableUpdates > bd.cfg.MaxHPACKTableUpdates {
		return fmt.Errorf("%w: %d table-size updates in one block > %d",
			ErrHPACKBudget, ac.tableUpdates, bd.cfg.MaxHPACKTableUpdates)
	}
	if ac.fields > bd.cfg.MaxHeaderFields {
		return fmt.Errorf("%w: %d header fields > %d",
			ErrHPACKBudget, ac.fields, bd.cfg.MaxHeaderFields)
	}
	if bd.connInserts+uint64(ac.inserts) > bd.cfg.MaxHPACKInsertsPerConn {
		return fmt.Errorf("%w: cumulative HPACK inserts %d > connection budget %d",
			ErrHPACKBudget, bd.connInserts+uint64(ac.inserts), bd.cfg.MaxHPACKInsertsPerConn)
	}
	return nil
}

// Decode runs the stateful decoder over a budget-checked block and returns
// the header fields. Dynamic-table inserts observed here are charged to the
// connection budget; on any cap violation the connection budget remains the
// authoritative backstop even if CheckBlock was skipped.
func (bd *BoundedDecoder) Decode(block []byte) ([]hpack.HeaderField, error) {
	if err := bd.CheckBlock(block); err != nil {
		return nil, err
	}
	hf, err := bd.dec.DecodeFull(block)
	if err != nil {
		return nil, err // DecodingError => COMPRESSION_ERROR at the caller
	}
	// Recompute the accounting from the actual scan so connection totals
	// match what the decoder really mutated.
	ac, _ := scanHPACK(block)
	bd.connInserts += uint64(ac.inserts)
	if bd.listSize > uint64(bd.cfg.MaxHeaderListSize) {
		return nil, fmt.Errorf("%w: decoded header list %d bytes > %d",
			ErrHPACKBudget, bd.listSize, bd.cfg.MaxHeaderListSize)
	}
	if uint32(len(hf)) > bd.cfg.MaxHeaderFields {
		return nil, fmt.Errorf("%w: %d decoded header fields > %d",
			ErrHPACKBudget, len(hf), bd.cfg.MaxHeaderFields)
	}
	bd.blockDone = true
	return hf, nil
}

// ConnInserts returns the cumulative dynamic-table inserts charged so far.
func (bd *BoundedDecoder) ConnInserts() uint64 { return bd.connInserts }
