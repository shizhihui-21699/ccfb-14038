package h2

import (
	"errors"
	"testing"

	"golang.org/x/net/http2/hpack"
)

func hpackTestConfig() *Config {
	c := DefaultConfig()
	c.HardMaxDynamicTableSize = 1024
	c.MaxHeaderBlockBytes = 256
	c.MaxContinuationFrames = 4
	c.MaxHeaderFields = 20
	c.MaxHeaderFieldSize = 256
	c.MaxHPACKInsertsPerBlock = 4
	c.MaxHPACKTableUpdates = 2
	c.MaxHPACKInsertsPerConn = 8
	c.MaxHeaderListSize = 2048
	return c
}

// encodeBlock builds a wire block with the given representations using the
// real hpack.Encoder, so tests exercise genuine byte sequences.
func encodeBlock(t *testing.T, fn func(e *hpack.Encoder)) []byte {
	t.Helper()
	var buf []byte
	e := hpack.NewEncoder(&byteWriter{buf: &buf})
	fn(e)
	return buf
}

type byteWriter struct{ buf *[]byte }

func (w *byteWriter) Write(p []byte) (int, error) {
	*w.buf = append(*w.buf, p...)
	return len(p), nil
}

func TestHPACKNormalBlockDecodes(t *testing.T) {
	cfg := hpackTestConfig()
	bd := NewBoundedDecoder(cfg)
	block := encodeBlock(t, func(e *hpack.Encoder) {
		e.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
		e.WriteField(hpack.HeaderField{Name: ":path", Value: "/video/seg1.m4s"})
		e.WriteField(hpack.HeaderField{Name: "user-agent", Value: "player/1.0"})
	})
	bd.BeginBlock()
	hf, err := bd.Decode(block)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(hf) != 3 {
		t.Fatalf("decoded %d fields, want 3", len(hf))
	}
	if hf[1].Value != "/video/seg1.m4s" {
		t.Fatalf("path=%q", hf[1].Value)
	}
}

// A block stuffed with literal-with-indexing representations trips the
// per-block insert budget before the dynamic table can be churned.
func TestHPACKInsertBudgetPerBlock(t *testing.T) {
	cfg := hpackTestConfig()
	bd := NewBoundedDecoder(cfg)
	block := encodeBlock(t, func(e *hpack.Encoder) {
		// Unique names force a real dynamic-table insert per field; a
		// repeated name would be served by an indexed reference and would
		// not exercise the insert budget.
		for i := 0; i < 10; i++ { // budget is 4
			e.WriteField(hpack.HeaderField{Name: "x-bomb-" + string(rune('a'+i)), Value: "a"})
		}
	})
	bd.BeginBlock()
	_, err := bd.Decode(block)
	if !errors.Is(err, ErrHPACKBudget) {
		t.Fatalf("err=%v, want ErrHPACKBudget", err)
	}
}

// The connection-wide insert budget catches slow churn across many small
// blocks: each block is individually legal, the cumulative table operations
// are not.
func TestHPACKInsertBudgetPerConnection(t *testing.T) {
	cfg := hpackTestConfig()
	cfg.MaxHPACKInsertsPerBlock = 2
	cfg.MaxHPACKInsertsPerConn = 5
	bd := NewBoundedDecoder(cfg)
	gotBudget := false
	for round := 0; round < 6; round++ {
		block := encodeBlock(t, func(e *hpack.Encoder) {
			e.WriteField(hpack.HeaderField{Name: "x-churn", Value: "v"})
			e.WriteField(hpack.HeaderField{Name: "x-churn2", Value: "w"})
		})
		bd.BeginBlock()
		if _, err := bd.Decode(block); err != nil {
			if errors.Is(err, ErrHPACKBudget) {
				gotBudget = true
				break
			}
			t.Fatalf("round %d unexpected err=%v", round, err)
		}
	}
	if !gotBudget {
		t.Fatal("connection insert budget never tripped")
	}
}

// A dynamic-table-size update above our hard cap is a syntax-level
// DecodingError (COMPRESSION_ERROR), distinct from a budget violation.
func TestHPACKTableSizeAboveHardCap(t *testing.T) {
	cfg := hpackTestConfig()
	bd := NewBoundedDecoder(cfg)
	block := encodeBlock(t, func(e *hpack.Encoder) {
		// Encoder limit is enforced separately; craft raw bytes for an
		// oversized update (0x3f prefix varint of 4096).
	})
	// 0x3f = size-update prefix all-ones, then varint continuation 4096-31.
	block = append(block, 0x3f)
	rest := uint64(4096) - 31
	for rest >= 128 {
		block = append(block, byte(rest)|0x80)
		rest >>= 7
	}
	block = append(block, byte(rest))
	bd.BeginBlock()
	_, err := bd.Decode(block)
	var de hpack.DecodingError
	if !errors.As(err, &de) {
		t.Fatalf("err=%v (%T), want hpack.DecodingError", err, err)
	}
}

// The raw-block size cap stops compression bombs regardless of how small
// the encoded form claims to be.
func TestHPACKRawBlockCap(t *testing.T) {
	cfg := hpackTestConfig()
	cfg.MaxHeaderBlockBytes = 8
	bd := NewBoundedDecoder(cfg)
	block := encodeBlock(t, func(e *hpack.Encoder) {
		e.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
		e.WriteField(hpack.HeaderField{Name: ":path", Value: "/abc"})
	})
	if len(block) <= 8 {
		t.Skip("encoder produced unexpectedly small block")
	}
	bd.BeginBlock()
	_, err := bd.Decode(block)
	if !errors.Is(err, ErrHPACKBudget) {
		t.Fatalf("err=%v, want ErrHPACKBudget", err)
	}
}

// Truncated/garbage bytes are a DecodingError, never a budget error: the
// caller must answer COMPRESSION_ERROR, not ENHANCE_YOUR_CALM.
func TestHPACKGarbageIsCompressionError(t *testing.T) {
	cfg := hpackTestConfig()
	bd := NewBoundedDecoder(cfg)
	bd.BeginBlock()
	_, err := bd.Decode([]byte{0x82, 0xff, 0xff, 0xff, 0xff, 0x07})
	var de hpack.DecodingError
	if !errors.As(err, &de) {
		t.Fatalf("err=%v (%T), want hpack.DecodingError", err, err)
	}
}

// The pre-scanner itself: counts match real representations.
func TestHPACKScannerCounts(t *testing.T) {
	block := encodeBlock(t, func(e *hpack.Encoder) {
		e.SetMaxDynamicTableSize(256)                            // 1 table update
		e.WriteField(hpack.HeaderField{Name: "x-a", Value: "1"}) // insert
		e.WriteField(hpack.HeaderField{Name: "x-b", Value: "2"}) // insert
		e.WriteField(hpack.HeaderField{Name: ":method", Value: "GET", Sensitive: true})
	})
	ac, err := scanHPACK(block)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if ac.inserts != 2 {
		t.Errorf("inserts=%d, want 2", ac.inserts)
	}
	if ac.tableUpdates != 1 {
		t.Errorf("tableUpdates=%d, want 1", ac.tableUpdates)
	}
	if ac.fields != 3 {
		t.Errorf("fields=%d, want 3", ac.fields)
	}
	if ac.rawLen != uint32(len(block)) {
		t.Errorf("rawLen=%d, want %d", ac.rawLen, len(block))
	}
}
