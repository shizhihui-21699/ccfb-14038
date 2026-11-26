package h2

import (
	"bytes"

	"golang.org/x/net/http2/hpack"
)

// hpackEncoder is a thin wrapper around hpack.Encoder that emits into a
// reusable buffer. One encoder belongs to one Conn and is used under
// writeMu, so its dynamic table stays synchronized with the peer's decoder
// without extra locking.
type hpackEncoder struct {
	enc *hpack.Encoder
	buf bytes.Buffer
}

func newHPACKEncoder(maxTableSize uint32) *hpackEncoder {
	e := &hpackEncoder{}
	e.enc = hpack.NewEncoder(&e.buf)
	e.enc.SetMaxDynamicTableSizeLimit(maxTableSize)
	e.enc.SetMaxDynamicTableSize(maxTableSize)
	return e
}

// SetMaxDynamicTableSize changes the table size in response to a peer
// SETTINGS_HEADER_TABLE_SIZE, clamped to our hard cap by the caller.
func (e *hpackEncoder) SetMaxDynamicTableSize(v uint32) {
	e.enc.SetMaxDynamicTableSize(v)
}

// WriteFields encodes a complete header block and returns its bytes. The
// returned slice is reused on the next call, so callers must hand it to the
// framer before invoking WriteFields again.
func (e *hpackEncoder) WriteFields(fields []hpack.HeaderField) []byte {
	e.buf.Reset()
	for _, f := range fields {
		// Encoder errors from hpack are limited to writer failures; our
		// writer is an in-memory buffer and cannot fail.
		_ = e.enc.WriteField(f)
	}
	return e.buf.Bytes()
}
