package main

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"time"

	mp "github.com/mackerelio/go-mackerel-plugin-helper"
	"golang.org/x/net/http2"
)

var (
	optHttpHeaders     headers
	optHttpMethod      string
	optPostBody        string
	optFollowRedirects bool
	optOnlyHeader      bool
	optInsecure        bool
	optClientCertFile  string
	optUrl             string
	// number of redirects followed
	redirectsFollowed int
)

const maxRedirects = 10

type HttpstatPlugin struct {
	Prefix string
}

type Plugin interface {
	GraphDefinition() map[string]mp.Graphs
	FetchMetrics() (map[string]interface{}, error)
}

func (s HttpstatPlugin) GraphDefinition() map[string](mp.Graphs) {
	labelPrefix := strings.Title(s.Prefix)
	return map[string](mp.Graphs){
		s.Prefix: mp.Graphs{
			Label: labelPrefix,
			Unit:  "integer",
			Metrics: [](mp.Metrics){
				mp.Metrics{Name: "dns_lookup", Label: "DNS Lookup", Stacked: true, Type: "uint32"},
				mp.Metrics{Name: "tcp_connection", Label: "TCP Connection", Stacked: true, Type: "uint32"},
				mp.Metrics{Name: "tls_handshake", Label: "TLS Handshake", Stacked: true, Type: "uint32"},
				mp.Metrics{Name: "server_processing", Label: "Server Processing", Stacked: true, Type: "uint32"},
				mp.Metrics{Name: "content_transfer", Label: "Content Transfer", Stacked: true, Type: "uint32"},
			},
		},
	}
}

func (s HttpstatPlugin) FetchMetrics() (map[string]interface{}, error) {
	url := parseURL(optUrl)
	stat, err := visit(url)
	if err != nil {
		return nil, fmt.Errorf("Faild to fetch HTTP stat: %s", err)
	}
	return stat, nil
}

func main() {
	flag.StringVar(&optHttpMethod, "X", "GET", "HTTP method to use")
	flag.StringVar(&optPostBody, "d", "", "the body of a POST or PUT request; from file use @filename")
	flag.BoolVar(&optFollowRedirects, "L", false, "follow 30x redirects")
	flag.BoolVar(&optOnlyHeader, "I", false, "don't read body of request")
	flag.BoolVar(&optInsecure, "k", false, "allow insecure SSL connections")
	flag.StringVar(&optClientCertFile, "E", "", "client cert file for tls config")
	flag.Var(&optHttpHeaders, "H", "set HTTP header; repeatable: -H 'Accept: ...' -H 'Range: ...'")
	flag.StringVar(&optUrl, "url", "", "client cert file for tls config")

	optPrefix := flag.String("metric-key-prefix", "httpstat", "Metric key prefix")
	optTempfile := flag.String("tempfile", "", "Temp file name")
	flag.Parse()

	s := HttpstatPlugin{
		Prefix: *optPrefix,
	}
	helper := mp.NewMackerelPlugin(s)
	helper.Tempfile = *optTempfile
	if helper.Tempfile == "" {
		hasher := md5.New()
		hasher.Write([]byte(optUrl))
		hash := hex.EncodeToString(hasher.Sum(nil))
		helper.Tempfile = fmt.Sprintf("/tmp/mackerel-plugin-%s-%s", *optPrefix, hash)
	}

	if (optHttpMethod == "POST" || optHttpMethod == "PUT") && optPostBody == "" {
		log.Fatal("must supply post body using -d when POST or PUT is used")
	}
	if optOnlyHeader {
		optHttpMethod = "HEAD"
	}
	helper.Run()
}

// readClientCert - helper function to read client certificate
// from pem formatted file
func readClientCert(filename string) []tls.Certificate {
	if filename == "" {
		return nil
	}
	var (
		pkeyPem []byte
		certPem []byte
	)

	// read client certificate file (must include client private key and certificate)
	certFileBytes, err := ioutil.ReadFile(optClientCertFile)
	if err != nil {
		log.Fatalf("failed to read client certificate file: %v", err)
	}

	for {
		block, rest := pem.Decode(certFileBytes)
		if block == nil {
			break
		}
		certFileBytes = rest

		if strings.HasSuffix(block.Type, "PRIVATE KEY") {
			pkeyPem = pem.EncodeToMemory(block)
		}
		if strings.HasSuffix(block.Type, "CERTIFICATE") {
			certPem = pem.EncodeToMemory(block)
		}
	}

	cert, err := tls.X509KeyPair(certPem, pkeyPem)
	if err != nil {
		log.Fatalf("unable to load client cert and key pair: %v", err)
	}
	return []tls.Certificate{cert}
}

func parseURL(uri string) *url.URL {
	if !strings.Contains(uri, "://") && !strings.HasPrefix(uri, "//") {
		uri = "//" + uri
	}

	url, err := url.Parse(uri)
	if err != nil {
		log.Fatalf("could not parse url %q: %v", uri, err)
	}

	if url.Scheme == "" {
		url.Scheme = "http"
		if !strings.HasSuffix(url.Host, ":80") {
			url.Scheme += "s"
		}
	}
	return url
}

func headerKeyValue(h string) (string, string) {
	i := strings.Index(h, ":")
	if i == -1 {
		log.Fatalf("Header '%s' has invalid format, missing ':'", h)
	}
	return strings.TrimRight(h[:i], " "), strings.TrimLeft(h[i:], " :")
}

// visit visits a url and times the interaction.
// If the response is a 30x, visit follows the redirect.
func visit(url *url.URL) (map[string]interface{}, error) {
	req := newRequest(optHttpMethod, url, optPostBody)

	var t0, t1, t2, t3, t4 time.Time

	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) { t0 = time.Now() },
		DNSDone:  func(_ httptrace.DNSDoneInfo) { t1 = time.Now() },
		ConnectStart: func(_, _ string) {
			if t1.IsZero() {
				// connecting to IP
				t1 = time.Now()
			}
		},
		ConnectDone: func(net, addr string, err error) {
			if err != nil {
				log.Fatalf("unable to connect to host %v: %v", addr, err)
			}
			t2 = time.Now()
		},
		GotConn:              func(_ httptrace.GotConnInfo) { t3 = time.Now() },
		GotFirstResponseByte: func() { t4 = time.Now() },
	}
	req = req.WithContext(httptrace.WithClientTrace(context.Background(), trace))

	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	switch url.Scheme {
	case "https":
		host, _, err := net.SplitHostPort(req.Host)
		if err != nil {
			host = req.Host
		}

		tr.TLSClientConfig = &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: optInsecure,
			Certificates:       readClientCert(optClientCertFile),
		}

		// Because we create a custom TLSClientConfig, we have to opt-in to HTTP/2.
		// See https://github.com/golang/go/issues/14275
		err = http2.ConfigureTransport(tr)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare transport for HTTP/2: %v", err)
		}
	}

	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// always refuse to follow redirects, visit does that
			// manually if required.
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	readResponseBody(req, resp)
	resp.Body.Close()

	t5 := time.Now() // after read body
	if t0.IsZero() {
		// we skipped DNS
		t0 = t1
	}

	fmta := func(d time.Duration) string {
		return fmt.Sprintf("%d", int(d/time.Millisecond))
	}

	if optFollowRedirects && isRedirect(resp) {
		loc, err := resp.Location()
		if err != nil {
			if err == http.ErrNoLocation {
				// 30x but no Location to follow, give up.
				return nil, fmt.Errorf("30x but no Location to follow, give up.: %v", err)
			}
			return nil, fmt.Errorf("unable to follow redirect: %v", err)
		}

		redirectsFollowed++
		if redirectsFollowed > maxRedirects {
			return nil, fmt.Errorf("maximum number of redirects (%d) followed", maxRedirects)
		}

		return visit(loc)
	}

	stat := make(map[string]interface{})
	stat["dns_lookup"] = fmta(t1.Sub(t0))
	stat["tcp_connection"] = fmta(t2.Sub(t1))
	stat["tls_handshake"] = fmta(t3.Sub(t2))
	stat["server_processing"] = fmta(t4.Sub(t3))
	stat["content_transfer"] = fmta(t5.Sub(t4))
	return stat, nil
}

func isRedirect(resp *http.Response) bool {
	return resp.StatusCode > 299 && resp.StatusCode < 400
}

func newRequest(method string, url *url.URL, body string) *http.Request {
	req, err := http.NewRequest(method, url.String(), createBody(body))
	if err != nil {
		log.Fatalf("unable to create request: %v", err)
	}
	for _, h := range optHttpHeaders {
		k, v := headerKeyValue(h)
		if strings.EqualFold(k, "host") {
			req.Host = v
			continue
		}
		req.Header.Add(k, v)
	}
	return req
}

func createBody(body string) io.Reader {
	if strings.HasPrefix(body, "@") {
		filename := body[1:]
		f, err := os.Open(filename)
		if err != nil {
			log.Fatalf("failed to open data file %s: %v", filename, err)
		}
		return f
	}
	return strings.NewReader(body)
}

// readResponseBody consumes the body of the response.
// readResponseBody returns an informational message about the
// disposition of the response body's contents.
func readResponseBody(req *http.Request, resp *http.Response) {
	if isRedirect(resp) || req.Method == http.MethodHead {
		return
	}

	w := ioutil.Discard
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Fatalf("failed to read response body: %v", err)
	}
	return
}

type headers []string

func (h headers) String() string {
	var o []string
	for _, v := range h {
		o = append(o, "-H "+v)
	}
	return strings.Join(o, " ")
}

func (h *headers) Set(v string) error {
	*h = append(*h, v)
	return nil
}

func (h headers) Len() int      { return len(h) }
func (h headers) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h headers) Less(i, j int) bool {
	a, b := h[i], h[j]

	// server always sorts at the top
	if a == "Server" {
		return true
	}
	if b == "Server" {
		return false
	}

	endtoend := func(n string) bool {
		// https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html#sec13.5.1
		switch n {
		case "Connection",
			"Keep-Alive",
			"Proxy-Authenticate",
			"Proxy-Authorization",
			"TE",
			"Trailers",
			"Transfer-Encoding",
			"Upgrade":
			return false
		default:
			return true
		}
	}

	x, y := endtoend(a), endtoend(b)
	if x == y {
		// both are of the same class
		return a < b
	}
	return x
}
