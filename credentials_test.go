package httpclient

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"net/url"
	"reflect"
	"sort"
	"testing"
	"time"
)

var orderedTest = []Credential{
	{Domain: "www.abc.example.com", Path: "/archive/all/2013/", Username: "a", Password: "a"},
	{Domain: "www.abc.example.com", Path: "/archive/all/2014/", Username: "b", Password: "b"},
	{Domain: "www.abc.example.com", Path: "/archive/all/", Username: "c", Password: "c"},
	{Domain: "abc.example.com", Path: "/content/", Username: "e", Password: "e"},
	{Domain: "def.example2.org", Path: "/", Username: "d", Password: "d"},
	{Domain: "ghi.example.org", Path: "/", Username: "f", Password: "f"},
	{Domain: "www.example.org", Path: "/", Username: "g", Password: "g"},
	{Domain: "example.org", Path: "/", Username: "h", Password: "h"},
	{Domain: "", Path: "", Username: "i", Password: "i"},
}

type LookupTest struct {
	Url      string
	Username string
	Password string
}

var lookupTests = []LookupTest{
	{"http://www.abc.example.com/archive/all/2013/", "a", "a"},
	{"http://www.abc.example.com/archive/all/2014/", "b", "b"},
	{"http://www.abc.example.com/archive/all/", "c", "c"},
	{"http://www.abc.example.com/archive/all/other/", "c", "c"},
	{"http://def.example2.org/content/", "d", "d"},
	{"http://www.example.org/some/path", "g", "g"},
	{"http://login.example.org/", "h", "h"},
	{"http://example.com/", "i", "i"},
}

func TestNewCredentialsJSON(t *testing.T) {
	buf := &bytes.Buffer{}

	enc := json.NewEncoder(buf)
	err := enc.Encode(unorderedSet())
	if err != nil {
		t.Fatalf("unable to encode credentials: %v", err)
	}

	r := bytes.NewReader(buf.Bytes())
	c, err := NewCredentialsJSON(r)
	if err != nil {
		t.Fatalf("NewJSONCredentials error: %v", err)
	}

	for i, v := range lookupTests {
		uri, err := url.Parse(v.Url)
		if err != nil {
			t.Error("%d: unable to parse %s: %v", i, v.Url, err)
			continue
		}
		u, p, err := c.Login(uri, "Login")
		if err != nil {
			t.Errorf("%d: expected credentials for %s, got an error: %v", i, v.Url, err)
		}
		if u != v.Username || p != v.Password {
			t.Errorf("%d: expected %s/%s, got %s/%s",
				i, v.Username, v.Password, u, p)
		}
	}
}

func TestOrderedCredentials(t *testing.T) {
	oc := &OrderedCredentials{
		v: unorderedSet(),
	}

	sort.Sort(oc)

	for i, v := range oc.v {
		if !reflect.DeepEqual(v, orderedTest[i]) {
			t.Errorf("c.v[%d]: expected %v got %v", i, orderedTest[i], v)
		}
	}
}

type DomainTest struct {
	Domain   string
	Test     string
	Expected bool
	Explain  string
}

var domainTests = []DomainTest{
	{"example.org", "example.org", true, "identical domains must match"},
	{"www.example.org", "www.Example.Org", true, "domains are case insensitive"},
	{"www.HighWire.ORG", "www.highwire.org", true, "domains are case insensitive"},
	{"example.org", "www.example.org", true, "a root domain matches its hosts"},
	{".example.org", "login.example.org", true, "a dot-prefixed domain matches any host within that domain"},
	{".example.org", "a1.login.example.org", true, "a dot-prefixed domain matches any host within that domain"},
	{".example.org", "example.org", false, "a dot-prefixed domain does not match the root domain"},
	{"example.org", "www.bmj.org", false, "different top-level domains, .com vs. .org, must not match"},
}

func TestCredentialDomainMatch(t *testing.T) {
	for i, v := range domainTests {
		c := NewCredential(v.Domain, "", "", "")
		if v.Expected != c.domainMatch(v.Test) {
			t.Errorf("%d: [%s] matching [%s] produced %v: expected %v (%s)",
				i, v.Test, c.Domain, !v.Expected, v.Expected, v.Explain)
		}
	}
}

type PathTest struct {
	Path     string
	Test     string
	Expected bool
	Explain  string
}

var pathTests = []PathTest{
	{"/", "/login", true, "prefix match and a trailing / for c.Path must match"},
	{"/protected/realm", "/protected/realm/1", true, "prefix match and a / following the overlapping text must match"},
	{"/login", "/", false, "no absolute equality and no prefix  match must not match"},
}

func TestCredentialPathMatch(t *testing.T) {
	for i, v := range pathTests {
		c := NewCredential("", v.Path, "", "")
		if v.Expected != c.pathMatch(v.Test) {
			t.Errorf("%d: [%s] matching [%s] produced %v: expected %v (%s)",
				i, v.Test, c.Path, !v.Expected, v.Expected, v.Explain)
		}
	}
}

func unorderedSet() []Credential {
	set := make([]Credential, len(orderedTest))
	copy(set, orderedTest)

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	n := len(set)
	for i := 0; i < n; i++ {
		j := r.Intn(n)
		set[i], set[j] = set[j], set[i]
	}

	return set
}
