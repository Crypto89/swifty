package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	log "github.com/sirupsen/logrus"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	target     = kingpin.Flag("target", "Target URL").Short('t').URL()
	listenAddr = kingpin.Flag("listen.addr", "Listen Address").Default("localhost:8080").String()
	secret     = kingpin.Flag("key", "Preshared key").Envar("SWIFTY_KEY").String()
	logLevel   = kingpin.Flag("log.level", "Set logging level").Short('l').Default("INFO").String()
	logFormat  = kingpin.Flag("log.format", "Log format").Short('f').Default("json").String()
)

func init() {
	kingpin.Parse()

	level, err := log.ParseLevel(*logLevel)
	if err != nil {
		log.Fatalf("Invalid log level: %s", err)
	}
	log.SetLevel(level)

	var format log.Formatter
	switch *logFormat {
	case "json":
		format = &log.JSONFormatter{}
	case "text":
		format = &log.TextFormatter{}
	default:
		log.Fatalf("Unknown format: %s", *logFormat)
	}
	log.SetFormatter(format)
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func newProxy(target *url.URL) *httputil.ReverseProxy {
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		req.URL.RawQuery = ""
		if _, ok := req.Header["User-Agent"]; !ok {
			req.Header.Set("User-Agent", "")
		}
	}
	return &httputil.ReverseProxy{Director: director}
}

func main() {
	proxy := newProxy(*target)
	http.Handle("/", wrap(proxy))

	log.Infof("listing on: %s", *listenAddr)
	http.ListenAndServe(*listenAddr, nil)
}

func wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Info(r.URL.String())
		if _, ok := r.URL.Query()["token"]; !ok || !checkHMAC(r.URL.Query()["token"][0], r.URL.Path) {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		h.ServeHTTP(w, r)
	})
}

func checkHMAC(token, path string) bool {
	tokenBytes, err := hex.DecodeString(token)
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, []byte(*secret))
	mac.Write([]byte(path))
	expected := mac.Sum(nil)
	log.Debugf("expected: %s", hex.EncodeToString(expected))

	return hmac.Equal(tokenBytes, expected)
}
