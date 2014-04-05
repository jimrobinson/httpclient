package httpclient

import (
	"fmt"
	"math/rand"
	"net/url"
	"sort"
	"testing"
	"time"
)

var _ = fmt.Println

var ordered = AuthPaths{
	{Path: "/1/2/3/4/5/", Auth: "a"},
	{Path: "/1/2/3/4/5", Auth: "b"},
	{Path: "/1/2/3/4", Auth: "c"},
	{Path: "/1/2/3", Auth: "d"},
	{Path: "/1/2", Auth: "e"},
	{Path: "/1", Auth: "f"},
	{Path: "/", Auth: "g"},
}

func TestAuthPathsSort(t *testing.T) {
	set := unorderedAuthPaths()
	sort.Sort(set)
	for i, v := range set {
		if v.Path != ordered[i].Path {
			t.Errorf("%d: expected %v, got %v\n", ordered[i], v)
		}
	}
}

type authPathMatchTest struct {
	Path    string
	Test    string
	Expect  bool
	Explain string
}

var authPathMatchTests = []authPathMatchTest{
	{"/1/2/3/4/5/", "/1/2/3/4/5.1", false, "Test path base is /1/2/3/4/, not /1/2/3/4/5/"},
	{"/1/2/3/4/5/", "/1/2/3/4/5/1.1", true, "Test path base is /1/2/3/4/5/"},
	{"/1/2/3", "/1/2/3/4", true, "Test path extends /1/2/3"},
}

func TestAuthPathMatches(t *testing.T) {
	for i, v := range authPathMatchTests {
		ap := AuthPath{Path: v.Path}
		if v.Expect != ap.Matches(v.Test) {
			t.Errorf("%d: %s matches %s returned %v, expected %v (%s)",
				i, v.Test, v.Path, !v.Expect, v.Expect, v.Explain)
		}
	}
}

func BenchmarkAuthPathsSort(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		set := unorderedAuthPaths()
		b.StartTimer()
		sort.Sort(set)
	}
}

func BenchmarkAuthPathsSet(b *testing.B) {
	ops := 10;
	uris := make([]*url.URL, ops)
	auth := make([]string, ops)

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	n := len(ordered)

	for i := 0; i < ops; i++ {
		j := r.Intn(n)
		uri, err := url.Parse(fmt.Sprintf("http://example.com%s", ordered[j].Path))
		if err != nil {
			b.Error(err)
		}
		uris[i] = uri
		auth[i] = ordered[j].Auth
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache := NewAuthCache()
		for j := 0; j < ops; j++ {
			cache.Set(uris[j], auth[j])
		}
	}
}

func unorderedAuthPaths() AuthPaths {
	set := make(AuthPaths, len(ordered))
	copy(set, ordered)

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	n := len(set)
	for i := 0; i < n; i++ {
		j := r.Intn(n)
		set[i], set[j] = set[j], set[i]
	}

	return set
}
