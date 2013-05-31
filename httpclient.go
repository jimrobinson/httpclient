package httpclient

import (
	"fmt"
	"net/http"
	"time"
)

// Client configures a timeout on the reciept of response headers
// and the read of response bodys from an http server.  It treats the
// configured timeout as absolute, not as a deadline.
type Client struct {
	Transport *http.Transport
	Client    *http.Client
	Timeout   time.Duration
}

// NewClient returns an Client configured to timeout requests
// that take longer than the specified timeout.
func NewClient(timeout time.Duration) (hr *Client) {

	transport := &http.Transport{
		ResponseHeaderTimeout: timeout,
	}

	client := &http.Client{
		Transport: transport,
	}

	hr = &Client{
		Transport: transport,
		Client:    client,
		Timeout:   timeout,
	}

	return
}

// Do sends an HTTP request and returns an HTTP response, following
// policy (e.g. redirects, cookies, auth) as configured on the client.
// If a non-zero timeout has been set on the Client, the request
// will be cancled if the duration has been reached before the request
// has completed.
func (hr *Client) Do(req *http.Request) (rsp *http.Response, err error) {

	rspCh := make(chan *http.Response)
	errCh := make(chan error)

	var timeoutCh <-chan time.Time
	if hr.Timeout > 0 {
		timeoutCh = time.After(hr.Timeout)
	}

	go func() {
		rsp, err = hr.Client.Do(req)
		if err != nil {
			errCh <- err
			rspCh <- rsp
		} else {
			rspCh <- rsp
		}
	}()

	var now time.Time

	select {
	case err = <-errCh:
		rsp = <-rspCh
		err = fmt.Errorf("error requesting %s: %v", req.URL, err)
	case now = <-timeoutCh:
		go hr.Transport.CancelRequest(req)
		err = fmt.Errorf("error requesting %s: read timed out at %s after waiting %s", req.URL, now.Format(time.RFC3339), hr.Timeout)
	case rsp = <-rspCh:
		err = nil
	}

	return
}
