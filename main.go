package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"

	log "github.com/sirupsen/logrus"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	target     = kingpin.Flag("target", "Target URL").Short('t').URL()
	listenAddr = kingpin.Flag("listen.addr", "Listen Address").Default("localhost:8080").String()
	secret     = kingpin.Flag("key", "Preshared key").Envar("SWIFTY_KEY").String()
	logLevel   = kingpin.Flag("log.level", "Set logging level").Short('l').Default("INFO").String()
	logFormat  = kingpin.Flag("log.format", "Log format").Short('f').Default("json").String()

	provider *gophercloud.ProviderClient
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

		req.Header.Set("X-Auth-Token", provider.Token())
	}
	return &httputil.ReverseProxy{Director: director}
}

func main() {
	if err := getProvider(); err != nil {
		log.Fatalf("%s", err)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	ctx, cancel := context.WithCancel(context.Background())

	go renewToken(ctx)

	h := http.Server{Addr: *listenAddr, Handler: nil}

	proxy := newProxy(*target)
	http.Handle("/", wrap(proxy))

	go func() {
		defer close(quit)

		log.Infof("listing on: %s", *listenAddr)
		if err := h.ListenAndServe(); err != nil {
			log.Fatalf("Could not listen: %s", err)
		}
	}()

	<-quit
	log.Debug("cancelling context")
	cancel()

	log.Info("Stopping webserver")
	sctx, scancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer scancel()

	if err := h.Shutdown(sctx); err != nil {
		log.Warnf("Failed to stop gracefully: %s", err)
	} else {
		log.Info("Server stopped gracefully")
	}

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

	return hmac.Equal(tokenBytes, expected)
}

func getProvider() error {
	authOpts, err := openstack.AuthOptionsFromEnv()
	if err != nil {
		return fmt.Errorf("Failed to get credentials from environment: %s", err)
	}

	provider, err = openstack.AuthenticatedClient(authOpts)
	if err != nil {
		return fmt.Errorf("Failed to create openstack client: %s", err)
	}

	return nil
}

func renewToken(ctx context.Context) {
	for {
		select {
		case <-time.After(1 * time.Minute):
			log.Infof("Renewing token")
			if err := provider.Reauthenticate(provider.Token()); err != nil {
				log.Fatalf("Failed to renew token: %s", err)
			}
			log.WithField("token", provider.Token()).Debugf("Token renewed")
		case <-ctx.Done():
			log.Info("Stopping token renew")
			return
		}

	}
}
