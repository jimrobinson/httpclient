package httpclient

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"sync"
)

type Session interface {
	Login(uri *url.URL, realm string) (username, password string, err error)

	Counter(nonce string) string

	CNonce() (cnonce string, err error)

	Authorization(uri *url.URL) (auth string)

	SetAuthorization(uri *url.URL, domain []string, auth string)

	DigestCredentials(uri *url.URL) (cred string)

	SetDigestCredentials(uri *url.URL, domain []string, cred string)

	DigestSession(server string) (sess string)

	SetDigestSession(server, value string)

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

func (session *session) Counter(nonce string) string {
	session.Lock()
	n := session.counter.Next(nonce)
	session.Unlock()
	return fmt.Sprintf("%08x", n)
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

func (session *session) Authorization(uri *url.URL) (auth string) {
	session.RLock()
	defer session.RUnlock()
	return session.authcache.Get(uri)
}

func (session *session) SetAuthorization(uri *url.URL, domain []string, auth string) {
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

func (session *session) DigestCredentials(uri *url.URL) (md5cred string) {
	session.RLock()
	defer session.RUnlock()
	// this isn't right, we need to set up something to allow
	// to prefix matching against paths
	return session.md5cred[uri.Host+":/"]
}

func (session *session) SetDigestCredentials(uri *url.URL, domain []string, cred string) {

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
		session.md5cred[space] = cred
	}
}

func (session *session) DigestSession(server string) (md5sess string) {
	session.RLock()
	defer session.RUnlock()
	return session.md5sess[server]
}

func (session *session) SetDigestSession(server, md5sess string) {
	session.Lock()
	defer session.Unlock()
	session.md5sess[server] = md5sess
}

func (session *session) NewProxyReadCloser() ProxyReadCloser {
	return NewMemFileReadCloser(session.rcDir, session.rcLimit)
}
