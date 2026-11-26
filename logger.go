package h2

import (
	"log"
	"os"
)

// Logger is the minimal logging surface Conn uses for security events
// (limiter transitions, refused streams, GOAWAY reasons). It matches the
// standard library *log.Logger, so no adapter is needed in most programs;
// pass nil to NewConnWithLogger (or use NewConn) to stay silent.
type Logger interface {
	Printf(format string, args ...any)
}

// noopLogger discards everything.
type noopLogger struct{}

func (noopLogger) Printf(string, ...any) {}

// stdLogger wraps the package default so the zero value still behaves.
type stdLogger struct{ l *log.Logger }

func (s stdLogger) Printf(format string, args ...any) { s.l.Printf(format, args...) }

// DefaultLogger writes to stderr with the standard flags.
func DefaultLogger() Logger {
	return stdLogger{l: log.New(os.Stderr, "h2: ", log.LstdFlags|log.Lmicroseconds)}
}

func noop() Logger { return noopLogger{} }
