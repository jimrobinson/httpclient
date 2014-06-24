package httpclient

import (
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"sort"
	"strings"
)

var NoCredentialsErr = errors.New("Matching login credentials not found")

type Credentials interface {
	Login(uri *url.URL, realm string) (username, password string, err error)
}

type Credential struct {
	Domain   string
	Path     string
	Username string
	Password string
}

func NewCredential(domain, path, username, password string) Credential {
	return Credential{
		Domain:   strings.ToLower(domain),
		Path:     path,
		Username: username,
		Password: password,
	}
}

func (c Credential) Matches(uri *url.URL) bool {
	return c.domainMatch(uri.Host) && c.pathMatch(uri.Path)
}

func (c Credential) domainMatch(domain string) bool {
	s := strings.ToLower(domain)
	if c.Domain == "" || c.Domain == s {
		return true
	}
	if strings.HasSuffix(s, c.Domain) && strings.Count(c.Domain, ".") >= 1 {
		if s[len(s)-len(c.Domain)-1] == '.' {
			return true
		}
	}
	return strings.HasPrefix(c.Domain, ".") && strings.HasSuffix(s, c.Domain)
}

func (c Credential) pathMatch(path string) bool {
	if c.Path == "" || c.Path == path {
		return true
	}
	if strings.HasPrefix(path, c.Path) {
		if strings.HasSuffix(c.Path, "/") {
			return true
		}
		return path[len(c.Path)] == '/'
	}
	return false
}

func NewCredentialsJSON(r io.Reader) (c Credentials, err error) {
	if r == nil {
		err = errors.New("nil io.Reader")
		return nil, err
	}

	oc := &OrderedCredentials{}
	v := make([]Credential, 0)

	dec := json.NewDecoder(r)
	err = dec.Decode(&v)
	if err == nil {
		for i := range v {
			v[i].Domain = strings.ToLower(v[i].Domain)
		}
		oc.v = v
		sort.Sort(oc)
	}

	return oc, err
}

type OrderedCredentials struct {
	v []Credential
}

func (c *OrderedCredentials) Login(uri *url.URL, realm string) (username, password string, err error) {
	for _, v := range c.v {
		if v.Matches(uri) {
			return v.Username, v.Password, nil
		}
	}
	// prompt for usernamse/password for realm could be made here
	return "", "", NoCredentialsErr
}

func (c *OrderedCredentials) Len() int      { return len(c.v) }
func (c *OrderedCredentials) Swap(i, j int) { c.v[i], c.v[j] = c.v[j], c.v[i] }
func (c *OrderedCredentials) Less(i, j int) bool {

	// sort non-empty domains before empty ones
	if c.v[i].Domain == "" && c.v[j].Domain != "" {
		return false
	} else if c.v[i].Domain != "" && c.v[j].Domain == "" {
		return true
	}

	// sort fully qualified domains before partial ones
	if !strings.HasPrefix(c.v[i].Domain, ".") && strings.HasPrefix(c.v[j].Domain, ".") {
		return true
	} else if strings.HasPrefix(c.v[i].Domain, ".") && !strings.HasPrefix(c.v[j].Domain, ".") {
		return false
	}

	// sort by number of domain components, longest to shortest
	a, b := strings.Count(c.v[i].Domain, "."), strings.Count(c.v[j].Domain, ".")
	if a > b {
		return true
	} else if a < b {
		return false
	}

	// sort by domain name
	if c.v[i].Domain < c.v[j].Domain {
		return true
	} else if c.v[i].Domain > c.v[j].Domain {
		return false
	}

	// sort by number of path components, longest to shortest
	a, b = strings.Count(c.v[i].Path, "/"), strings.Count(c.v[j].Path, "/")
	if a > b {
		return true
	} else if a < b {
		return false
	}

	// sort by path string
	return c.v[i].Path < c.v[j].Path
}
