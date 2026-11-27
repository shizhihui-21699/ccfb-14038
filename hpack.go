package h2guard

import (
	"errors"

	"golang.org/x/net/http2/hpack"
)

// errHeaderListTooLarge is returned when the decoded header list exceeds
// the configured limit. The size accounting (name + value + 32 per field)
// matches RFC 7540 §6.5.2 SETTINGS_MAX_HEADER_LIST_SIZE.
var errHeaderListTooLarge = errors.New("h2guard: decoded header list too large")

// boundedDecoder wraps hpack.Decoder with hard limits:
//
//   - the dynamic table is capped at maxDynTable bytes. We advertise the
//     same value in SETTINGS_HEADER_TABLE_SIZE, so a larger table-size
//     update is a decode error, surfaced as GOAWAY(COMPRESSION_ERROR)
//     per RFC 7541 §4.2;
//   - the decoded field list is capped at maxListBytes, so a header
//     block full of tiny literal fields cannot expand into unbounded
//     memory (the "HPACK bomb" shape).
//
// Input-side limits (compressed bytes per block, CONTINUATION count,
// assembly deadline) live in the connection's header-block assembler.
//
// Note that decoding always runs to completion even after the list cap
// trips: HPACK state is connection-scoped, so every block must be
// decoded to keep the compression context in sync with the peer.
type boundedDecoder struct {
	dec       *hpack.Decoder
	maxList   uint32
	listSize  uint32
	fields    []hpack.HeaderField
	oversized bool
}

func newBoundedDecoder(maxDynTable, maxListBytes uint32) *boundedDecoder {
	bd := &boundedDecoder{maxList: maxListBytes}
	bd.dec = hpack.NewDecoder(maxDynTable, func(f hpack.HeaderField) {
		if bd.oversized {
			return
		}
		bd.listSize += uint32(len(f.Name) + len(f.Value) + 32)
		if bd.listSize > bd.maxList {
			bd.oversized = true
			return
		}
		bd.fields = append(bd.fields, f)
	})
	return bd
}

// begin resets per-header-block state. The dynamic table persists across
// blocks, as HPACK requires.
func (bd *boundedDecoder) begin() {
	bd.fields = bd.fields[:0]
	bd.listSize = 0
	bd.oversized = false
}

// write feeds one HEADERS/CONTINUATION fragment.
func (bd *boundedDecoder) write(p []byte) error {
	_, err := bd.dec.Write(p)
	return err
}

// finish ends the header block and returns the decoded fields. The
// returned slice is a copy: the decoder's internal buffer is reused for
// the next block, which may be decoded while a handler is still reading
// these headers.
func (bd *boundedDecoder) finish() ([]hpack.HeaderField, error) {
	if err := bd.dec.Close(); err != nil {
		return nil, err
	}
	if bd.oversized {
		return nil, errHeaderListTooLarge
	}
	return append([]hpack.HeaderField(nil), bd.fields...), nil
}
