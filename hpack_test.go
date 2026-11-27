package h2guard

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"golang.org/x/net/http2/hpack"
)

func TestBoundedDecoderListCap(t *testing.T) {
	bd := newBoundedDecoder(4096, 128)
	bd.begin()
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
	enc.WriteField(hpack.HeaderField{Name: "x-big", Value: strings.Repeat("a", 500)})
	if err := bd.write(buf.Bytes()); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := bd.finish(); !errors.Is(err, errHeaderListTooLarge) {
		t.Fatalf("finish error = %v, want errHeaderListTooLarge", err)
	}
}

func TestBoundedDecoderNormal(t *testing.T) {
	bd := newBoundedDecoder(4096, 4096)
	bd.begin()
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
	enc.WriteField(hpack.HeaderField{Name: ":path", Value: "/watch"})
	if err := bd.write(buf.Bytes()); err != nil {
		t.Fatalf("write: %v", err)
	}
	fields, err := bd.finish()
	if err != nil {
		t.Fatalf("finish: %v", err)
	}
	if len(fields) != 2 || fields[1].Value != "/watch" {
		t.Fatalf("fields = %+v", fields)
	}
}

func TestBoundedDecoderRejectsOversizedTableUpdate(t *testing.T) {
	bd := newBoundedDecoder(4096, 4096)
	bd.begin()
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	enc.SetMaxDynamicTableSizeLimit(8192)
	enc.SetMaxDynamicTableSize(8192) // beyond the decoder's 4096 limit
	enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
	if err := bd.write(buf.Bytes()); err == nil {
		t.Fatal("expected dynamic table size update error")
	}
}
