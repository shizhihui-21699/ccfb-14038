// Command h2proxyd is a worked example of wrapping a backend with the
// hardened h2 frame layer. It terminates HTTPS/HTTP-2 on :8443 and proxies
// every request to an upstream HTTP/2 server, illustrating the one
// integration contract that makes Rapid Reset accounting accurate:
// r.MarkDispatched() is called once the upstream call is actually in
// flight, never earlier.
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	h2 "videogate/h2"

	"golang.org/x/net/http2/hpack"
)

func main() {
	listenAddr := flag.String("listen", ":8443", "TLS listen address")
	upstream := flag.String("upstream", "https://127.0.0.1:9443", "upstream origin")
	certFile := flag.String("cert", "server.pem", "TLS certificate")
	keyFile := flag.String("key", "server.key", "TLS private key")
	flag.Parse()

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("load keypair: %v", err)
	}

	ln, err := tls.Listen("tcp", *listenAddr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("h2 proxy listening on %s, upstream %s", *listenAddr, *upstream)

	handler := newProxyHandler(*upstream)
	lg := log.New(os.Stderr, "h2: ", log.LstdFlags|log.Lmicroseconds)

	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(raw, handler, lg)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	_ = ln.Close()
}

func serve(raw net.Conn, handler h2.Handler, lg h2.Logger) {
	// Every connection gets its own limiter, decoder state and budgets —
	// one abusive client can never consume another's headroom.
	cfg := h2.DefaultConfig()
	conn := h2.NewConnWithLogger(raw, cfg, handler, lg)
	if err := conn.Serve(); err != nil {
		lg.Printf("connection ended: %v", err)
	}
}

// proxyHandler forwards a request over net/http (HTTP/2 to an https
// upstream) and streams the response back through the hardened frame layer.
func newProxyHandler(upstream string) h2.Handler {
	client := &http.Client{Transport: &http.Transport{ForceAttemptHTTP2: true}}
	return h2.HandlerFunc(func(r *h2.Request, w *h2.Responder) {
		req, err := http.NewRequestWithContext(r.Context(), r.Method, upstream+r.Path, r.Body())
		if err != nil {
			_ = w.Headers(502)
			_ = w.EndStream()
			return
		}
		for _, hf := range r.Headers {
			if !hf.IsPseudo() {
				req.Header.Add(hf.Name, hf.Value)
			}
		}

		// The critical ordering: the upstream call is in flight before we
		// mark dispatched. A client reset before this point is a phantom
		// (cancel-before-work) stream and feeds Rapid Reset detection; a
		// reset after it is an ordinary seek-cancel that cannot degrade
		// the connection by itself.
		resp, err := client.Do(req)
		r.MarkDispatched()
		if err != nil {
			_ = w.Headers(502)
			_ = w.EndStream()
			return
		}
		defer resp.Body.Close()

		var fields []hpack.HeaderField
		for name, vals := range resp.Header {
			for _, v := range vals {
				fields = append(fields, hpack.HeaderField{Name: name, Value: v})
			}
		}
		if err := w.Headers(resp.StatusCode, fields...); err != nil {
			return
		}

		buf := make([]byte, 32*1024)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return // client reset or connection closing
				}
			}
			if err != nil {
				break
			}
		}
		_ = w.EndStream()
	})
}
