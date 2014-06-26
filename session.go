package httpclient

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"sync"
)

type Session interface {
	// Login returns a username and password for a specified uri
	// and relam, or an error.  If no authentication credentials
	// could be found, NoCredentialsErr should be returned.
	Login(uri *url.URL, realm string) (username, password string, err error)

	// CNonce returns a random nonce for use in Digest authentication.
	CNonce() (cnonce string, err error)

	// Counter returns a hexidecimal string indicating the number
	// of times that the specified nonce has been passed to
	// Counter.
	Counter(nonce string) string

	// SetAuthorization caches the Authenticate header value for
	// the specified uri and domains.
	SetAuthorization(uri *url.URL, domain []string, auth string)

	// Authorization returns the Authenticate header value cached
	// for the specified uri
	Authorization(uri *url.URL) (auth string)

	// SetDigestCredentials caches the specified credentials hash
	// string for the specified uri host and domains.  If domain
	// is an empty array, then the domain "/" is assumed.
	SetDigestCredentials(uri *url.URL, domain []string, hash string)

	// DigestCredentials returns the cached credentials hash
	// string for the specified uri host.
	DigestCredentials(uri *url.URL) (hash string)

	// SetDigestSession caches the specified session hash string
	// for the specified server
	SetDigestSession(server, hash string)

	// DigestSession returns the cached session hash string for
	// the specified server
	DigestSession(server string) (hash string)

	// Duplicate creates n clones of rc.  The returned io.ReadCloser
	// must be closed by the caller.  The original rc will always
	// be closed when the function returns.
	Duplicate(rc io.ReadCloser, n int) (clone []io.ReadCloser, err error)

	// NewProxyReadCloser returns an implementation of ProxyReadCloser,
	// useful for processing a request Body without losing the
	// ability to then send the Body in a subsequent request.
	NewProxyReadCloser() ProxyReadCloser
}

type session struct {
	sync.RWMutex
	credentials Credentials
	authcache   *AuthCache
	md5cred     map[string]string
	md5sess     map[string]string
	counter     *NonceCounter
	rcDir       string
	rcLimit     int
}

// NewSession returns an implementation of Session.  The provided
// credentials will be used to return login usernames and passwords.
// nonceCap sets the limit on the number nonce values cached by
// the nonce Counter.  dir specifies the temporary directory to use
// when cloning an io.Reader via NewProxyReadCloser, and limit indicates
// the in-memory limit for cloning data, after which the clone will
// be written to a temporary file in dir.  If dir is the empty string,
// the OS default temporary directory will be used.
func NewSession(credentials Credentials, nonceCap int, dir string, limit int) Session {
	return &session{
		credentials: credentials,
		authcache:   NewAuthCache(),
		md5cred:     make(map[string]string),
		md5sess:     make(map[string]string),
		counter:     NewNonceCounter(nonceCap),
		rcDir:       dir,
		rcLimit:     limit,
	}
}

func (session *session) Login(uri *url.URL, realm string) (username, password string, err error) {
	return session.credentials.Login(uri, realm)
}

func (session *session) CNonce() (cnonce string, err error) {
	buf := make([]byte, 12)
	_, err = rand.Read(buf)
	if err != nil {
		return
	}
	cnonce = base64.StdEncoding.EncodeToString(buf)
	return
}

func (session *session) Counter(nonce string) string {
	session.Lock()
	n := session.counter.Next(nonce)
	session.Unlock()
	return fmt.Sprintf("%08x", n)
}

func (session *session) SetAuthorization(uri *url.URL, domain []string, auth string) {
	session.Lock()
	defer session.Unlock()

	if domain == nil || len(domain) == 0 {
		root := &url.URL{
			Scheme:   uri.Scheme,
			Opaque:   uri.Opaque,
			User:     uri.User,
			Host:     uri.Host,
			Path:     "/",
			RawQuery: "",
			Fragment: "",
		}
		session.authcache.Set(root, auth)
		return
	}

	for _, s := range domain {
		ref, err := url.Parse(s)
		if err == nil {
			session.authcache.Set(uri.ResolveReference(ref), auth)
		}
	}
}

func (session *session) Authorization(uri *url.URL) (auth string) {
	session.RLock()
	defer session.RUnlock()
	return session.authcache.Get(uri)
}

func (session *session) SetDigestCredentials(uri *url.URL, domain []string, hash string) {
	if len(domain) == 0 {
		domain = append(domain, "/")
	}

	spaces := make([]string, len(domain))
	for _, s := range domain {
		ref, err := url.Parse(s)
		if err == nil {
			abs := uri.ResolveReference(ref)
			spaces = append(spaces, abs.Host+":"+abs.Path)
		}
	}

	session.Lock()
	defer session.Unlock()
	for _, space := range spaces {
		session.md5cred[space] = hash
	}
}

func (session *session) DigestCredentials(uri *url.URL) (hash string) {
	session.RLock()
	defer session.RUnlock()
	return session.md5cred[uri.Host+":/"]
}

func (session *session) SetDigestSession(server, hash string) {
	session.Lock()
	defer session.Unlock()
	session.md5sess[server] = hash
}

func (session *session) DigestSession(server string) (hash string) {
	session.RLock()
	defer session.RUnlock()
	return session.md5sess[server]
}

func (session *session) Duplicate(rc io.ReadCloser, n int) (clone []io.ReadCloser, err error) {
	defer rc.Close()

	prc := make([]ProxyReadCloser, n)
	for i := 0; i < n; i++ {
		prc[i] = session.NewProxyReadCloser()
	}

	writers := make([]io.Writer, n)
	for i := 0; i < n; i++ {
		writers[i] = prc[i].(io.Writer)
	}

	mw := io.MultiWriter(writers...)

	_, err = io.Copy(mw, rc)
	if err != nil {
		err = fmt.Errorf("error cloning io.ReadCloser: %v", err)
		return
	}

	for i := 0; i < n; i++ {
		err = prc[i].Close()
		if err != nil {
			for j := i; j < n; j++ {
				prc[i].Close()
				x, _ := prc[i].ReadCloser()
				if x != nil {
					x.Close()
				}
			}
			err = fmt.Errorf("error cloning io.ReadCloser: %v", err)
			return
		}
	}

	clone = make([]io.ReadCloser, n)
	for i := 0; i < n; i++ {
		clone[i], err = prc[i].ReadCloser()
		if err != nil {
			for j := 0; j < n; j++ {
				clone[i].Close()
			}
			clone = nil
			err = fmt.Errorf("error cloning io.ReadCloser: %v", err)
			return
		}
	}

	return clone, err
}

func (session *session) NewProxyReadCloser() ProxyReadCloser {
	return NewMemFileReadCloser(session.rcDir, session.rcLimit)
}
