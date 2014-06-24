package httpclient

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"github.com/jimrobinson/lexrec"
	"github.com/jimrobinson/trace"
	"io"
	"net/http"
	"strings"
)

type Challenges []*Challenge

type Challenge struct {
	Scheme    string
	Realm     string
	Domain    []string
	Nonce     string
	Opaque    string
	Stale     bool
	Algorithm string
	Qop       []string
}

func (challenge *Challenge) Authorization(session Session, req *http.Request) (auth string, err error) {
	switch challenge.Scheme {
	case "Basic":
		auth, err = challenge.Basic(session, req)
	case "Digest":
		auth, err = challenge.Digest(session, req)
	default:
		err = fmt.Errorf("unrecognized authorization scheme: %s", challenge.Scheme)
	}
	return
}

func (challenge *Challenge) Basic(session Session, req *http.Request) (auth string, err error) {
	username, password, err := session.Login(req.URL, challenge.Realm)
	if err != nil {
		return
	}

	data := []byte(fmt.Sprintf("%s:%s", username, password))

	auth = fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString(data))

	return auth, nil
}

func (challenge *Challenge) Digest(session Session, req *http.Request) (auth string, err error) {

	username, password, err := session.Login(req.URL, challenge.Realm)
	if err != nil {
		return
	}

	// client nonce
	var cnonce string
	cnonce, err = session.CNonce()
	if err != nil {
		return
	}

	// quality of protection
	var qop string
	for _, v := range challenge.Qop {
		switch v {
		case "auth":
			if qop != "auth-int" {
				qop = v
			}
		case "auth-int":
			qop = v
		}
	}

	// nonce counter value
	var nc string
	if qop != "" {
		nc = session.Counter(challenge.Nonce)
	}

	// RFC 2617 3.2.2.2 A1
	var ha1 string

	switch challenge.Algorithm {
	case "", "MD5", "MD5-sess":
		ha1 = session.DigestCredentials(req.URL)
		if ha1 == "" {
			h := md5.New()

			io.WriteString(h, username)
			io.WriteString(h, ":")
			io.WriteString(h, challenge.Realm)
			io.WriteString(h, ":")
			io.WriteString(h, password)

			ha1 = fmt.Sprintf("%x", h.Sum(nil))

			session.SetDigestCredentials(req.URL, challenge.Domain, ha1)
		}
	default:
		err = fmt.Errorf("unhandled algorithm: %s", challenge.Algorithm)
		return
	}

	if challenge.Algorithm == "MD5-sess" {
		md5sess := session.DigestSession(req.Host)

		if md5sess == "" {
			h := md5.New()

			io.WriteString(h, ha1)
			io.WriteString(h, ":")
			io.WriteString(h, challenge.Nonce)
			io.WriteString(h, ":")
			io.WriteString(h, cnonce)

			md5sess = fmt.Sprintf("%x", h.Sum(nil))
			session.SetDigestSession(req.Host, md5sess)
		}

		ha1 = md5sess
	}

	// RFC 2617 3.2.2.3 A2
	var ha2 string

	if qop == "" || qop == "auth" {
		// A2 = Method ":" digest-uri-value

		h := md5.New()
		io.WriteString(h, req.Method)
		io.WriteString(h, ":")
		io.WriteString(h, req.URL.RequestURI())

		ha2 = fmt.Sprintf("%x", h.Sum(nil))

	} else if qop == "auth-int" {
		// A2 = Method ":" digest-uri-value ":" H(entity-body)

		h := md5.New()

		io.WriteString(h, req.Method)
		io.WriteString(h, ":")
		io.WriteString(h, req.URL.RequestURI())
		io.WriteString(h, ":")

		hb := md5.New()
		if req.Body != nil {
			prc := session.NewProxyReadCloser()
			mw := io.MultiWriter(hb, prc)

			_, err = io.Copy(mw, req.Body)
			if err != nil {
				return
			}

			err = prc.Close()
			if err != nil {
				return
			}

			req.Body, err = prc.ReadCloser()
			if err != nil {
				return
			}
		}
		io.WriteString(h, fmt.Sprintf("%x", hb.Sum(nil)))

		ha2 = fmt.Sprintf("%x", h.Sum(nil))
	}

	// RFC 2617 3.2.2.1 Request-Digest
	var digest string
	if qop == "auth" || qop == "auth-int" {
		// KD ( H(A1), unq(nonce-value) ":" nc-value : unq(cnonce-value) ":" unq(qop-value) : H(A2)
		// KD (secret, data) = H (concat(secret, ":", data))

		h := md5.New()

		io.WriteString(h, ha1)
		io.WriteString(h, ":")
		io.WriteString(h, challenge.Nonce)
		io.WriteString(h, ":")
		io.WriteString(h, nc)
		io.WriteString(h, ":")
		io.WriteString(h, cnonce)
		io.WriteString(h, ":")
		io.WriteString(h, qop)
		io.WriteString(h, ":")
		io.WriteString(h, ha2)

		digest = fmt.Sprintf("%x", h.Sum(nil))

	} else {
		// KD ( H(A1), unq(nonce-value) ":" H(A2)
		// KD (secret, data) = H (concat(secret, ":", data))

		h := md5.New()

		io.WriteString(h, ha1)
		io.WriteString(h, ":")
		io.WriteString(h, challenge.Nonce)
		io.WriteString(h, ":")
		io.WriteString(h, ha2)

		digest = fmt.Sprintf("%x", h.Sum(nil))
	}

	// Authorization header is built up in buf
	buf := &bytes.Buffer{}

	buf.WriteString(fmt.Sprintf(`Digest username="%s"`, username))

	buf.WriteString(fmt.Sprintf(`, realm="%s"`, challenge.Realm))

	buf.WriteString(fmt.Sprintf(`, nonce="%s"`, challenge.Nonce))

	buf.WriteString(fmt.Sprintf(`, uri="%s"`, req.URL.RequestURI()))

	if qop != "" {
		buf.WriteString(fmt.Sprintf(`, qop=%s`, qop))
		buf.WriteString(fmt.Sprintf(`, nc=%s`, nc))
		buf.WriteString(fmt.Sprintf(`, cnonce="%s"`, cnonce))
	}

	if challenge.Algorithm != "" {
		buf.WriteString(fmt.Sprintf(`, algorithm=%s`, challenge.Algorithm))
	}

	buf.WriteString(fmt.Sprintf(`, response="%s"`, digest))

	if challenge.Opaque != "" {
		buf.WriteString(fmt.Sprintf(`, opaque="%s"`, challenge.Opaque))
	}

	auth = buf.String()

	return auth, err
}

func Authentication(rsp *http.Response) (authentication Challenges, err error) {
	var set Challenges
	for _, v := range rsp.Header[http.CanonicalHeaderKey("WWW-Authenticate")] {
		set, err = parseChallenge(v)
		if err != nil {
			return nil, err
		}
		authentication = append(authentication, set...)
	}
	return
}

func parseChallenge(challenge string) (parsed Challenges, err error) {
	traceFn, traceT := trace.M(traceId, trace.Trace)

	r := strings.NewReader(challenge)
	rec := lexrec.NewRecord(256, nil, func(l *lexrec.Lexer) {})

	var l *lexrec.Lexer
	l, err = lexrec.NewLexerRun("ParseChallenge", r, rec, emitWWWAuthenticate)
	if err != nil {
		return nil, err
	}

	for {
		item := l.NextItem()
		if item.Type == lexrec.ItemEOF {
			break
		} else if item.Type == lexrec.ItemError {
			err = fmt.Errorf("error at position %d: %s", item.Pos, item.Value)
			break
		}

		switch item.Type {
		case ItemDigest:
			parsed = append(parsed, &Challenge{Scheme: item.Value})
		case ItemBasic:
			parsed = append(parsed, &Challenge{Scheme: item.Value})
		case ItemRealm:
			if i := len(parsed) - 1; i >= 0 {
				parsed[i].Realm = item.Value[1 : len(item.Value)-1]
			}
		case ItemDomain:
			if i := len(parsed) - 1; i >= 0 {
				parsed[i].Domain = strings.Fields(item.Value[1 : len(item.Value)-1])
			}
		case ItemNonce:
			if i := len(parsed) - 1; i >= 0 {
				parsed[i].Nonce = item.Value[1 : len(item.Value)-1]
			}
		case ItemOpaque:
			if i := len(parsed) - 1; i >= 0 {
				parsed[i].Opaque = item.Value[1 : len(item.Value)-1]
			}
		case ItemStale:
			if i := len(parsed) - 1; i >= 0 {
				if item.Value == "true" {
					parsed[i].Stale = true
				} else {
					parsed[i].Stale = false
				}
			}
		case ItemAlgorithm:
			if i := len(parsed) - 1; i >= 0 {
				parsed[i].Algorithm = item.Value
			}
		case ItemQop:
			if i := len(parsed) - 1; i >= 0 {
				options := strings.Split(item.Value[1:len(item.Value)-1], ",")
				parsed[i].Qop = options
			}
		case ItemAuthParam:
			if traceT {
				trace.T(traceFn, "skipping unrecognized auth-param: %s", item.Value)
			}
		default:
			err = fmt.Errorf("unhandled item type %d at position %d: %v", item.Type, item.Pos, item.Value)
			return
		}
	}

	return
}
