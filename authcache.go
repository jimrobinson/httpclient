package httpclient

import (
	"net/url"
	"sort"
	"strings"
)

type AuthCache struct {
	Domain map[string]AuthPaths
}

func NewAuthCache() *AuthCache {
	return &AuthCache{
		Domain: make(map[string]AuthPaths),
	}
}

func (c *AuthCache) Get(uri *url.URL) (auth string) {
	paths, ok := c.Domain[uri.Host]
	if !ok {
		return
	}
	for _, v := range paths {
		if v.Matches(uri.Path) {
			return v.Auth
		}
	}
	return
}

func (c *AuthCache) Set(uri *url.URL, auth string) {
	pairs := c.Domain[uri.Host]
	if pairs != nil {
		for _, v := range pairs {
			if v.Path == uri.Path {
				v.Auth = auth
				return
			}
		}
	}
	pairs = append(pairs, AuthPath{Path: uri.Path, Auth: auth})
	sort.Sort(pairs)
	c.Domain[uri.Host] = pairs
}

type AuthPaths []AuthPath

type AuthPath struct {
	Path string
	Auth string
}

func (ap AuthPath) Matches(path string) bool {
	if ap.Path == path {
		return true
	}
	if strings.HasPrefix(path, ap.Path) {
		n := len(ap.Path)
		return (ap.Path[n-1] == '/' || path[n] == '/')
	}
	return false
}

func (p AuthPaths) Len() int      { return len(p) }
func (p AuthPaths) Swap(i, j int) { p[i], p[j] = p[j], p[i] }
func (p AuthPaths) Less(i, j int) bool {
	if p[i].Path == "/" && p[j].Path != "/" {
		return false
	}
	if p[i].Path != "/" && p[j].Path == "/" {
		return true
	}
	a, b := strings.Count(p[i].Path, "/"), strings.Count(p[j].Path, "/")
	if a > b {
		return true
	}
	if a < b {
		return false
	}
	return p[i].Path < p[j].Path
}
