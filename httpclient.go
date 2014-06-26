package httpclient

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

var traceId = "github.com/jimrobinson/httpclient"

// Client configures a timeout on the reciept of response headers and
// the read of response bodys from an http server.  It treats the
// configured timeout as absolute, not as a deadline that resets per
// successful read operation.
type Client struct {
	http.Client
	Transport *http.Transport
	Timeout   time.Duration
}

// NewClient returns an Client configured to timeout requests
// that take longer than the specified timeout.
func NewClient(timeout time.Duration) (hr *Client) {

	transport := &http.Transport{
		ResponseHeaderTimeout: timeout,
	}

	client := http.Client{
		Transport: transport,
	}

	hr = &Client{
		Client:    client,
		Transport: transport,
		Timeout:   timeout,
	}

	return
}

// Do sends an HTTP request and returns an HTTP response, following
// policy (e.g. redirects, cookies, auth) as configured on the client.
// If a non-zero timeout has been set on the Client, the request will
// be cancled if the duration has been reached before the request has
// completed.
func (hr *Client) Do(req *http.Request) (rsp *http.Response, err error) {
	rspCh := make(chan *http.Response)
	errCh := make(chan error)

	var timeoutCh <-chan time.Time
	if hr.Timeout > 0 {
		timeoutCh = time.After(hr.Timeout)
	}

	go func(req *http.Request) {
		rsp, err := hr.Client.Do(req)
		if err != nil {
			errCh <- err
			rspCh <- rsp
		} else {
			rspCh <- rsp
		}
	}(req)

	var now time.Time

	select {
	case err = <-errCh:
		rsp = <-rspCh
	case now = <-timeoutCh:
		go hr.Transport.CancelRequest(req)
		err = fmt.Errorf("error requesting %s: read timed out at %s after waiting %s",
			req.URL, now.Format(time.RFC3339), hr.Timeout)
	case rsp = <-rspCh:
		err = nil
	}

	return
}

// AuthDo performs the same work as Do, but additionally
// attempts to handle WWW-Authenticate requests using
// the provided session.  An error is returned if the session
// is nil.
func (hr *Client) AuthDo(req *http.Request, session Session) (rsp *http.Response, err error) {
	if session == nil {
		err = fmt.Errorf("invalid session: nil")
		return
	}

	auth := session.Authorization(req.URL)
	if auth != "" {
		req.Header.Add("Authorization", auth)
	}

	// copy the request body if it's possible we will have to
	// retry the request
	var body io.ReadCloser
	if auth == "" && req.Body != nil {
		var clone []io.ReadCloser
		clone, err = session.Duplicate(req.Body, 2)
		if err != nil {
			return
		}

		req.Body, body = clone[0], clone[1]
		defer req.Body.Close()
		defer body.Close()
	}

	rsp, err = hr.Do(req)

	// retry the request w/ Authorization if challenged
	if err == nil && rsp.StatusCode == http.StatusUnauthorized {
		var challenges Challenges
		challenges, err = Authentication(rsp)
		if err != nil {
			err = fmt.Errorf("unable to parse %s WWW-Authenticate: %v", req.URL.String(), err)
			return
		}

		n := len(challenges)
		if n == 0 {
			err = fmt.Errorf("unable to parse %s WWW-Authenticate header: %s",
				req.URL.String(), rsp.Header.Get("Www-Authenticate"))
			return
		}

		for i, challenge := range challenges {
			lastTry := i+1 == n

			auth, err = challenge.Authorization(session, req)
			if err != nil {
				if err == NoCredentialsErr && !lastTry {
					continue
				}
				return
			}

			if auth != "" {
				req.Header.Add("Authorization", auth)

				// if  the request body is not nil
				// and we have additional challenges
				// we may need to try, then we have
				// to keep cloning the request body.
				if body != nil {
					if lastTry {
						req.Body = body
					} else {
						var clone []io.ReadCloser
						clone, err = session.Duplicate(body, 2)
						if err != nil {
							return
						}

						req.Body, body = clone[0], clone[1]
						defer req.Body.Close()
						defer body.Close()
					}
				}

				rsp, err = hr.Do(req)
				if err == nil && rsp.StatusCode != http.StatusUnauthorized {
					session.SetAuthorization(req.URL, challenge.Domain, auth)
					return
				}
			}
		}
	}

	return
}
