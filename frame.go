package h2

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Frame types, RFC 9113 §11.2.
const (
	FrameData         Type = 0x0
	FrameHeaders      Type = 0x1
	FramePriority     Type = 0x2
	FrameRSTStream    Type = 0x3
	FrameSettings     Type = 0x4
	FramePushPromise  Type = 0x5
	FramePing         Type = 0x6
	FrameGoAway       Type = 0x7
	FrameWindowUpdate Type = 0x8
	FrameContinuation Type = 0x9
)

// Type is an HTTP/2 frame type.
type Type uint8

func (t Type) String() string {
	switch t {
	case FrameData:
		return "DATA"
	case FrameHeaders:
		return "HEADERS"
	case FrameRSTStream:
		return "RST_STREAM"
	case FrameSettings:
		return "SETTINGS"
	case FramePing:
		return "PING"
	case FrameGoAway:
		return "GOAWAY"
	case FrameWindowUpdate:
		return "WINDOW_UPDATE"
	case FrameContinuation:
		return "CONTINUATION"
	case FramePriority:
		return "PRIORITY"
	case FramePushPromise:
		return "PUSH_PROMISE"
	default:
		return fmt.Sprintf("UNKNOWN(0x%x)", uint8(t))
	}
}

// Frame flags, RFC 9113 §11.
const (
	FlagEndStream  Flags = 0x1
	FlagAck        Flags = 0x1
	FlagEndHeaders Flags = 0x4
	FlagPadded     Flags = 0x8
	FlagPriority   Flags = 0x20
)

// Flags is the bit field of frame flags.
type Flags uint8

func (f Flags) Has(v Flags) bool { return f&v != 0 }
func (f Flags) String() string {
	var buf []byte
	add := func(b byte, c string) {
		if f&Flags(b) != 0 {
			if len(buf) > 0 {
				buf = append(buf, '|')
			}
			buf = append(buf, c...)
		}
	}
	add(0x1, "END_STREAM/ACK")
	add(0x4, "END_HEADERS")
	add(0x8, "PADDED")
	add(0x20, "PRIORITY")
	if len(buf) == 0 {
		return "0"
	}
	return string(buf)
}

const (
	// FrameHeaderLen is the fixed length of an HTTP/2 frame header.
	FrameHeaderLen = 9
	// MaxFrameSizeFloor / MaxFrameSizeCeiling bound SETTINGS_MAX_FRAME_SIZE.
	MaxFrameSizeFloor   = 16384
	MaxFrameSizeCeiling = 16777215
	// ClientPreface is the HTTP/2 connection preface sent by clients.
	ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
)

// FrameHeader is the parsed 9-octet frame header.
type FrameHeader struct {
	Length   uint32
	Type     Type
	Flags    Flags
	StreamID uint32 // low 31 bits; high bit always stripped
}

// Frame is one parsed frame. Payload is owned by the Framer and reused on
// the next ReadFrame call, so callers must copy anything they retain.
type Frame struct {
	FrameHeader
	Payload []byte
}

// Settings identifiers, RFC 9113 §6.5.2.
const (
	SettingHeaderTableSize      uint16 = 0x1
	SettingEnablePush           uint16 = 0x2
	SettingInitialWindowSize    uint16 = 0x4
	SettingMaxFrameSize         uint16 = 0x5
	SettingMaxConcurrentStreams uint16 = 0x3
	SettingMaxHeaderListSize    uint16 = 0x6
)

// Setting is one SETTINGS parameter.
type Setting struct {
	ID    uint16
	Value uint32
}

// Reader is the read side of an HTTP/2 transport. It enforces only framing
// rules that exist below the state machine: maximum frame size and exact
// payload lengths. Everything semantic lives in Conn.
type Reader struct {
	r            io.Reader
	maxFrameSize uint32
	hdrBuf       [FrameHeaderLen]byte
	payload      []byte
}

// NewReader returns a frame Reader. maxFrameSize is the initial value
// (SETTINGS_MAX_FRAME_SIZE floor before any SETTINGS exchange); Conn updates
// it via SetMaxFrameSize when the peer negotiates a larger one.
func NewReader(r io.Reader, maxFrameSize uint32) *Reader {
	if maxFrameSize < MaxFrameSizeFloor {
		maxFrameSize = MaxFrameSizeFloor
	}
	return &Reader{r: r, maxFrameSize: maxFrameSize}
}

// SetMaxFrameSize updates the largest acceptable payload. The value must
// already have been range-checked (RFC 9113 §6.5.2).
func (fr *Reader) SetMaxFrameSize(n uint32) {
	fr.maxFrameSize = n
}

// ReadFrame reads exactly one frame. A payload exceeding the negotiated
// maximum returns FRAME_SIZE_ERROR so the caller can answer with GOAWAY.
func (fr *Reader) ReadFrame() (*Frame, error) {
	if _, err := io.ReadFull(fr.r, fr.hdrBuf[:]); err != nil {
		return nil, err
	}
	h := FrameHeader{
		Length:   uint32(fr.hdrBuf[0])<<16 | uint32(fr.hdrBuf[1])<<8 | uint32(fr.hdrBuf[2]),
		Type:     Type(fr.hdrBuf[3]),
		Flags:    Flags(fr.hdrBuf[4]),
		StreamID: binary.BigEndian.Uint32(fr.hdrBuf[5:]) & 0x7fffffff,
	}
	if h.Length > fr.maxFrameSize {
		return nil, connError(ErrCodeFrameSize,
			fmt.Sprintf("%s frame payload %d exceeds SETTINGS_MAX_FRAME_SIZE %d",
				h.Type, h.Length, fr.maxFrameSize))
	}
	if cap(fr.payload) < int(h.Length) {
		fr.payload = make([]byte, h.Length)
	}
	fr.payload = fr.payload[:h.Length]
	if _, err := io.ReadFull(fr.r, fr.payload); err != nil {
		return nil, err
	}
	return &Frame{FrameHeader: h, Payload: fr.payload}, nil
}

// Writer is the write side of an HTTP/2 transport. All methods are safe for
// serial use by Conn; concurrent goroutines must go through Conn's write
// mutex.
type Writer struct {
	w            io.Writer
	maxFrameSize uint32
	hdrBuf       [FrameHeaderLen]byte
}

// NewWriter returns a frame Writer.
func NewWriter(w io.Writer, maxFrameSize uint32) *Writer {
	if maxFrameSize < MaxFrameSizeFloor {
		maxFrameSize = MaxFrameSizeFloor
	}
	return &Writer{w: w, maxFrameSize: maxFrameSize}
}

func (fw *Writer) writeHeader(typ Type, flags Flags, streamID uint32, length int) {
	b := fw.hdrBuf[:]
	b[0] = byte(length >> 16)
	b[1] = byte(length >> 8)
	b[2] = byte(length)
	b[3] = byte(typ)
	b[4] = byte(flags)
	binary.BigEndian.PutUint32(b[5:], streamID&0x7fffffff)
}

// WriteRaw writes a complete frame with an already-assembled payload.
func (fw *Writer) WriteRaw(typ Type, flags Flags, streamID uint32, payload []byte) error {
	fw.writeHeader(typ, flags, streamID, len(payload))
	if _, err := fw.w.Write(fw.hdrBuf[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := fw.w.Write(payload)
		return err
	}
	return nil
}

// WriteSettings sends a non-ACK SETTINGS frame.
func (fw *Writer) WriteSettings(ss []Setting) error {
	p := make([]byte, 6*len(ss))
	for i, s := range ss {
		binary.BigEndian.PutUint16(p[i*6:], s.ID)
		binary.BigEndian.PutUint32(p[i*6+2:], s.Value)
	}
	return fw.WriteRaw(FrameSettings, 0, 0, p)
}

// WriteSettingsAck sends SETTINGS with the ACK bit.
func (fw *Writer) WriteSettingsAck() error {
	return fw.WriteRaw(FrameSettings, FlagAck, 0, nil)
}

// WritePing sends a PING frame (ack=true sets the ACK flag).
func (fw *Writer) WritePing(ack bool, data [8]byte) error {
	var f Flags
	if ack {
		f = FlagAck
	}
	return fw.WriteRaw(FramePing, f, 0, data[:])
}

// WriteGoAway sends a GOAWAY frame. debugData may be empty.
func (fw *Writer) WriteGoAway(lastStreamID uint32, code ErrorCode, debugData []byte) error {
	p := make([]byte, 8+len(debugData))
	binary.BigEndian.PutUint32(p[0:], lastStreamID&0x7fffffff)
	binary.BigEndian.PutUint32(p[4:], uint32(code))
	copy(p[8:], debugData)
	return fw.WriteRaw(FrameGoAway, 0, 0, p)
}

// WriteRSTStream sends a RST_STREAM frame.
func (fw *Writer) WriteRSTStream(streamID uint32, code ErrorCode) error {
	var p [4]byte
	binary.BigEndian.PutUint32(p[:], uint32(code))
	return fw.WriteRaw(FrameRSTStream, 0, streamID, p[:])
}

// WriteWindowUpdate sends a WINDOW_UPDATE frame (stream 0 = connection level).
func (fw *Writer) WriteWindowUpdate(streamID uint32, inc uint32) error {
	var p [4]byte
	binary.BigEndian.PutUint32(p[:], inc&0x7fffffff)
	return fw.WriteRaw(FrameWindowUpdate, 0, streamID, p[:])
}

// WriteData splits data into DATA frames no larger than maxFrameSize. The
// final frame carries END_STREAM when endStream is true.
func (fw *Writer) WriteData(streamID uint32, data []byte, endStream bool) error {
	max := int(fw.maxFrameSize)
	for len(data) > 0 {
		n := len(data)
		if n > max {
			n = max
		}
		var flags Flags
		if n == len(data) && endStream {
			flags = FlagEndStream
		}
		if err := fw.WriteRaw(FrameData, flags, streamID, data[:n]); err != nil {
			return err
		}
		data = data[n:]
	}
	if endStream && len(data) == 0 {
		// Zero-length terminal DATA for empty bodies.
		return fw.WriteRaw(FrameData, FlagEndStream, streamID, nil)
	}
	return nil
}

// HeaderBlockWriter buffers a header block and emits HEADERS plus, if
// necessary, CONTINUATION frames honoring END_HEADERS and END_STREAM.
type HeaderBlockWriter struct {
	fw *Writer
}

// NewHeaderBlockWriter returns a HeaderBlockWriter bound to fw.
func NewHeaderBlockWriter(fw *Writer) *HeaderBlockWriter {
	return &HeaderBlockWriter{fw: fw}
}

// WriteHeaders writes the reassembled block. It handles the HEADERS payload
// trimming (pad/priority fields are the caller's responsibility; this method
// takes a block that is already a pure HPACK block) and CONTINUATION
// chaining.
func (h *HeaderBlockWriter) WriteHeaders(streamID uint32, endStream bool, block []byte) error {
	max := int(h.fw.maxFrameSize)
	first := true
	for {
		n := len(block)
		last := n <= max
		if last {
			n = len(block)
		} else {
			n = max
		}
		var flags Flags
		if last {
			flags |= FlagEndHeaders
		}
		if endStream && first {
			flags |= FlagEndStream
		}
		typ := FrameHeaders
		if !first {
			typ = FrameContinuation
			flags &^= FlagEndStream // only valid on HEADERS
		}
		if err := h.fw.WriteRaw(typ, flags, streamID, block[:n]); err != nil {
			return err
		}
		if last {
			return nil
		}
		block = block[n:]
		first = false
	}
}
