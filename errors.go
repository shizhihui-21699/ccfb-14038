// Package h2 implements a hardened HTTP/2 frame processing layer for a
// reverse proxy. It sits directly on top of a net.Conn (or any io.ReadWriter
// implementing the Framer transport) and enforces three classes of bounds
// before application code is ever touched:
//
//   - per-connection stream creation / reset accounting with adaptive
//     concurrency degradation (RFC 9113 §5.1.2, CVE-2023-44487 "Rapid Reset"),
//   - hard caps on header-block decoding cost: raw block size, number of
//     CONTINUATION frames, decoded header-list size, HPACK dynamic-table
//     size and cumulative dynamic-table operations (HPACK bomb /
//     "CONTINUATION flood", CVE-2024-27316 style attacks),
//   - protocol-valid frame state machine checks, so every violation is
//     answered with the error code RFC 9113 prescribes rather than a
//     connection drop that looks like a server crash.
package h2

// ErrorCode is an HTTP/2 error code (RFC 9113 §7).
type ErrorCode uint32

const (
	ErrCodeNoError            ErrorCode = 0x0
	ErrCodeProtocol           ErrorCode = 0x1
	ErrCodeInternal           ErrorCode = 0x2
	ErrCodeFlowControl        ErrorCode = 0x3
	ErrCodeSettingsTimeout    ErrorCode = 0x4
	ErrCodeStreamClosed       ErrorCode = 0x5
	ErrCodeFrameSize          ErrorCode = 0x6
	ErrCodeRefusedStream      ErrorCode = 0x7
	ErrCodeCancel             ErrorCode = 0x8
	ErrCodeCompression        ErrorCode = 0x9
	ErrCodeConnect            ErrorCode = 0xa
	ErrCodeEnhanceYourCalm    ErrorCode = 0xb
	ErrCodeInadequateSecurity ErrorCode = 0xc
	ErrCodeHTTP11Required     ErrorCode = 0xd
)

func (e ErrorCode) String() string {
	switch e {
	case ErrCodeNoError:
		return "NO_ERROR"
	case ErrCodeProtocol:
		return "PROTOCOL_ERROR"
	case ErrCodeInternal:
		return "INTERNAL_ERROR"
	case ErrCodeFlowControl:
		return "FLOW_CONTROL_ERROR"
	case ErrCodeSettingsTimeout:
		return "SETTINGS_TIMEOUT"
	case ErrCodeStreamClosed:
		return "STREAM_CLOSED"
	case ErrCodeFrameSize:
		return "FRAME_SIZE_ERROR"
	case ErrCodeRefusedStream:
		return "REFUSED_STREAM"
	case ErrCodeCancel:
		return "CANCEL"
	case ErrCodeCompression:
		return "COMPRESSION_ERROR"
	case ErrCodeConnect:
		return "CONNECT_ERROR"
	case ErrCodeEnhanceYourCalm:
		return "ENHANCE_YOUR_CALM"
	case ErrCodeInadequateSecurity:
		return "INADEQUATE_SECURITY"
	case ErrCodeHTTP11Required:
		return "HTTP_1_1_REQUIRED"
	default:
		return "UNKNOWN_ERROR_CODE"
	}
}

// StreamError carries an HTTP/2 error that applies to a single stream and is
// delivered with a RST_STREAM frame.
type StreamError struct {
	StreamID uint32
	Code     ErrorCode
	reason   string
}

func (e *StreamError) Error() string {
	return "h2: stream " + itoa(e.StreamID) + " error " + e.Code.String() + ": " + e.reason
}

// ConnError carries an HTTP/2 error that applies to the whole connection and
// is delivered with a GOAWAY frame.
type ConnError struct {
	Code   ErrorCode
	reason string
}

func (e *ConnError) Error() string {
	return "h2: connection error " + e.Code.String() + ": " + e.reason
}

func streamError(id uint32, code ErrorCode, reason string) *StreamError {
	return &StreamError{StreamID: id, Code: code, reason: reason}
}

func connError(code ErrorCode, reason string) *ConnError {
	return &ConnError{Code: code, reason: reason}
}

func itoa(v uint32) string {
	if v == 0 {
		return "0"
	}
	var buf [16]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
