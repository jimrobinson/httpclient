package httpclient

import (
	"bytes"
	"net/http"
	"reflect"
	"testing"
)

var basicChallenge = Challenge{
	Scheme: "Basic",
	Realm:  "WallyWorld",
}

var digestChallenge1 = Challenge{
	Scheme: "Digest",
	Realm:  "testrealm@host.com",
	Qop:    []string{"auth", "auth-int"},
	Nonce:  "dcd98b7102dd2f0e8b11d0f600bfb0c093",
	Opaque: "5ccc069c403ebaf9f0171e9517f40e41",
}

type ParseExpect struct {
	Challenge string
	Parsed    []*Challenge
}

var parseTests = []ParseExpect{
	{`	Basic
			realm="WallyWorld"`,
		[]*Challenge{
			&basicChallenge,
		},
	},
	{`	Digest 
			realm="testrealm@host.com",
			qop="auth,auth-int",
			nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
			opaque="5ccc069c403ebaf9f0171e9517f40e41"`,
		[]*Challenge{
			&digestChallenge1,
		},
	},
	{`	Basic
			realm="WallyWorld",
		Digest 
			realm="testrealm@host.com",
			qop="auth,auth-int",
			nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
			opaque="5ccc069c403ebaf9f0171e9517f40e41"`,
		[]*Challenge{
			&basicChallenge,
			&digestChallenge1,
		},
	},
}

func TestParseChallenge(t *testing.T) {
	for i, v := range parseTests {
		p, err := parseChallenge(v.Challenge)
		if err != nil {
			t.Errorf("failed parseTests[%d]: %v", i, err)
		}

		if len(p) != len(v.Parsed) {
			t.Errorf("failed parseTests[%d]: parsed %d instead of %d challenges: %s",
				i, len(p), len(v.Parsed), v.Challenge)
		}

		for j, c := range v.Parsed {
			if !reflect.DeepEqual(p[j], c) {
				t.Errorf("parseTests[%d][%d]: not DeepEqual:\n%v\n%v\n",
					i, j, p[j], c)
			}
		}
	}
}

func TestBasicChallenge(t *testing.T) {

	username := "Aladdin"
	password := "open sesame"
	expected := "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="

	credentials := &OrderedCredentials{[]Credential{NewCredential("example.com", "/", username, password)}}
	challenge := &basicChallenge

	session := NewSession(credentials, 1000, "", -1)

	req, err := http.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}

	auth, err := challenge.Basic(session, req)
	if err != nil {
		t.Fatal(err)
	}

	if auth != expected {
		t.Errorf("expected [%s], got [%s]", expected, auth)
	}
}

type testSession struct {
	Session
}

func (ts *testSession) CNonce() (string, error) {
	return "0a4f113b", nil
}

func TestDigestChallenge(t *testing.T) {

	username := "Mufasa"
	password := "Circle Of Life"
	expected := `Digest username="Mufasa", realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/dir/index.html", qop=auth, nc=00000001, cnonce="0a4f113b", response="6629fae49393a05397450978507c4ef1", opaque="5ccc069c403ebaf9f0171e9517f40e41"`

	credentials := &OrderedCredentials{[]Credential{NewCredential("host.com", "/", username, password)}}
	challenge := &digestChallenge1
	challenge.Qop = []string{"auth"}

	session := &testSession{NewSession(credentials, 1000, "", -1)}

	req, err := http.NewRequest("GET", "http://host.com/dir/index.html", nil)
	if err != nil {
		t.Fatal(err)
	}

	auth, err := challenge.Digest(session, req)
	if err != nil {
		t.Fatal(err)
	}

	if auth != expected {
		t.Errorf("expected [%s], got [%s]", expected, auth)
	}
}

func BenchmarkParseChallenge(b *testing.B) {
	buf := &bytes.Buffer{}
	for i, v := range parseTests {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(v.Challenge)
	}

	s := buf.String()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := parseChallenge(s)
		if err != nil {
			b.Fatal(err)
		}
	}
}
