// Package h2guard is a defensive HTTP/2 frame-handling layer for reverse
// proxies. It implements the connection state machine with built-in
// mitigations for the known HTTP/2 abuse vectors:
//
//   - rapid stream reset (CVE-2023-44487): streams cost nothing until
//     END_HEADERS; early resets are token-bucketed and the connection's
//     concurrency limit is degraded step by step, ending in
//     GOAWAY(ENHANCE_YOUR_CALM);
//   - CONTINUATION flood (CVE-2024-27316): hard caps on header-block
//     bytes, CONTINUATION frame count, and assembly time;
//   - HPACK abuse: a small advertised dynamic table, a hard cap on the
//     decoded header list, and a rate limit on compressed header bytes.
//
// The layer speaks the protocol correctly throughout: attackers and
// unlucky legit clients get the exact error codes RFC 7540/7541 require,
// and refused streams use REFUSED_STREAM so browsers can safely retry.
package h2guard

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

// RFC 7540 §6 frame types.
const (
	frameData         uint8 = 0x0
	frameHeaders      uint8 = 0x1
	framePriority     uint8 = 0x2
	frameRSTStream    uint8 = 0x3
	frameSettings     uint8 = 0x4
	framePushPromise  uint8 = 0x5
	framePing         uint8 = 0x6
	frameGoAway       uint8 = 0x7
	frameWindowUpdate uint8 = 0x8
	frameContinuation uint8 = 0x9
)

// Frame flags shared by several types.
const (
	flagEndStream  uint8 = 0x1
	flagAck        uint8 = 0x1
	flagEndHeaders uint8 = 0x4
	flagPadded     uint8 = 0x8
	flagPriority   uint8 = 0x20
)

// RFC 7540 §7 error codes.
const (
	errCodeNo                uint32 = 0x0
	errCodeProtocol          uint32 = 0x1
	errCodeInternal          uint32 = 0x2
	errCodeFlowControl       uint32 = 0x3
	errCodeSettingsTimeout   uint32 = 0x4
	errCodeStreamClosed      uint32 = 0x5
	errCodeFrameSize         uint32 = 0x6
	errCodeRefusedStream     uint32 = 0x7
	errCodeCancel            uint32 = 0x8
	errCodeCompression       uint32 = 0x9
	errCodeConnect           uint32 = 0xa
	errCodeEnhanceYourCalm   uint32 = 0xb
	errCodeInadequateSecurity uint32 = 0xc
)

// SETTINGS identifiers, RFC 7540 §6.5.2.
const (
	settingHeaderTableSize      uint16 = 0x1
	settingEnablePush           uint16 = 0x2
	settingMaxConcurrentStreams uint16 = 0x3
	settingInitialWindowSize    uint16 = 0x4
	settingMaxFrameSize         uint16 = 0x5
	settingMaxHeaderListSize    uint16 = 0x6
)

const frameHeaderLen = 9

type frameHeader struct {
	length   uint32
	typ      uint8
	flags    uint8
	streamID uint32
}

type frame struct {
	frameHeader
	payload []byte
}

// frameTooLargeError is returned by readFrame when the peer exceeds our
// advertised SETTINGS_MAX_FRAME_SIZE. RFC 7540 §4.2 makes this a
// connection error of type FRAME_SIZE_ERROR.
type frameTooLargeError struct {
	length uint32
	max    uint32
}

func (e *frameTooLargeError) Error() string {
	return fmt.Sprintf("h2guard: frame of %d bytes exceeds max frame size %d", e.length, e.max)
}

// readFrame reads one frame. buf is scratch space, grown on demand; the
// returned payload aliases it and is only valid until the next readFrame
// call with the same buf. The 24-bit length is checked against maxFrame
// before any allocation, so a hostile length prefix cannot force a large
// allocation.
func readFrame(r io.Reader, maxFrame uint32, buf []byte) (frame, error) {
	var fh frame
	var hdr [frameHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return fh, err
	}
	length := uint32(hdr[0])<<16 | uint32(hdr[1])<<8 | uint32(hdr[2])
	if length > maxFrame {
		return fh, &frameTooLargeError{length: length, max: maxFrame}
	}
	if uint32(len(buf)) < length {
		buf = make([]byte, length)
	}
	payload := buf[:length]
	if _, err := io.ReadFull(r, payload); err != nil {
		return fh, err
	}
	fh.length = length
	fh.typ = hdr[3]
	fh.flags = hdr[4]
	fh.streamID = binary.BigEndian.Uint32(hdr[5:9]) & 0x7fffffff
	fh.payload = payload
	return fh, nil
}

// frameWriter serializes frames. It is safe for concurrent use by the
// read loop and per-stream handler goroutines.
type frameWriter struct {
	w  io.Writer
	mu sync.Mutex
}

func (fw *frameWriter) writeFrame(typ, flags uint8, streamID uint32, payload []byte) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	var hdr [frameHeaderLen]byte
	n := len(payload)
	hdr[0] = byte(n >> 16)
	hdr[1] = byte(n >> 8)
	hdr[2] = byte(n)
	hdr[3] = typ
	hdr[4] = flags
	binary.BigEndian.PutUint32(hdr[5:9], streamID&0x7fffffff)
	if _, err := fw.w.Write(hdr[:]); err != nil {
		return err
	}
	if n > 0 {
		if _, err := fw.w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

type setting struct {
	id  uint16
	val uint32
}

func (fw *frameWriter) writeSettings(s ...setting) error {
	p := make([]byte, 0, 6*len(s))
	for _, kv := range s {
		var b [6]byte
		binary.BigEndian.PutUint16(b[0:2], kv.id)
		binary.BigEndian.PutUint32(b[2:6], kv.val)
		p = append(p, b[:]...)
	}
	return fw.writeFrame(frameSettings, 0, 0, p)
}

func (fw *frameWriter) writeSettingsAck() error {
	return fw.writeFrame(frameSettings, flagAck, 0, nil)
}

// writeGoAway sends GOAWAY (RFC 7540 §6.8). lastStreamID is the highest
// stream that was or might have been processed; debug is opaque
// diagnostic data — keep it short and free of attacker-controlled bytes.
func (fw *frameWriter) writeGoAway(lastStreamID uint32, code uint32, debug string) error {
	p := make([]byte, 8, 8+len(debug))
	binary.BigEndian.PutUint32(p[0:4], lastStreamID&0x7fffffff)
	binary.BigEndian.PutUint32(p[4:8], code)
	p = append(p, debug...)
	return fw.writeFrame(frameGoAway, 0, 0, p)
}

func (fw *frameWriter) writeRSTStream(streamID, code uint32) error {
	var p [4]byte
	binary.BigEndian.PutUint32(p[:], code)
	return fw.writeFrame(frameRSTStream, 0, streamID, p[:])
}

func (fw *frameWriter) writePingAck(data [8]byte) error {
	return fw.writeFrame(framePing, flagAck, 0, data[:])
}

func (fw *frameWriter) writeWindowUpdate(streamID, inc uint32) error {
	var p [4]byte
	binary.BigEndian.PutUint32(p[:], inc&0x7fffffff)
	return fw.writeFrame(frameWindowUpdate, 0, streamID, p[:])
}
