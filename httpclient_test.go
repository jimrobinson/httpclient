package httpclient

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"
)

type httpTestHandler struct {
	*sync.Mutex
	count int
}

const delayHeader = "X-HttpTestHandler-Delay"

func (h *httpTestHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h.Lock()
	h.count++
	n := h.count
	h.Unlock()

	var wait time.Duration
	if s := req.Header.Get(delayHeader); s != "" {
		sec, err := strconv.Atoi(s)
		if err == nil && sec > 0 {
			wait = time.Duration(sec)
		}
	}
	if wait > 0 {
		<-time.After(wait)
	}

	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("test #%d waited for %s", n, wait)))
}

func TestDo(t *testing.T) {

	timeout := time.Duration(1 * time.Second)
	client := NewClient(timeout)

	server := httptest.NewServer(&httpTestHandler{Mutex: new(sync.Mutex)})
	defer server.CloseClientConnections()
	defer server.Close()

	baseURI, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	for i := 1; i <= 2; i++ {
		baseURI.Path = fmt.Sprintf("/test-%d", i)

		req, err := http.NewRequest("GET", baseURI.String(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if i == 2 {
			req.Header.Add(delayHeader, fmt.Sprintf("%d", timeout*2))
		}

		rsp, err := client.Do(req)
		if err != nil {
			if i == 1 {
				t.Fatal(err)
			}
		} else {
			if i == 2 {
				t.Error("test #2 should have timed out, but didn't.")
			}

			_, err := ioutil.ReadAll(rsp.Body)
			if err != nil {
				t.Fatal(err)
			}
			rsp.Body.Close()
		}
	}
}

func BenchmarkClient(b *testing.B) {
	timeout := time.Duration(1 * time.Second)
	client := NewClient(timeout)

	server := httptest.NewServer(&httpTestHandler{Mutex: new(sync.Mutex)})
	defer server.CloseClientConnections()
	defer server.Close()

	baseURI, err := url.Parse(server.URL)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		baseURI.Path = fmt.Sprintf("/test-%d", i)

		req, err := http.NewRequest("GET", baseURI.String(), nil)
		if err != nil {
			b.Fatal(err)
		}

		rsp, err := client.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		_, err = ioutil.ReadAll(rsp.Body)
		if err != nil {
			b.Fatal(err)
		}
		rsp.Body.Close()
	}
}

func BenchmarkDefaultClient(b *testing.B) {
	server := httptest.NewServer(&httpTestHandler{Mutex: new(sync.Mutex)})
	defer server.CloseClientConnections()
	defer server.Close()

	baseURI, err := url.Parse(server.URL)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		baseURI.Path = fmt.Sprintf("/test-%d", i)

		req, err := http.NewRequest("GET", baseURI.String(), nil)
		if err != nil {
			b.Fatal(err)
		}

		rsp, err := http.DefaultClient.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		_, err = ioutil.ReadAll(rsp.Body)
		if err != nil {
			b.Fatal(err)
		}
		rsp.Body.Close()
	}
}
