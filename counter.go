package httpclient

import (
	"container/list"
)

// NonceCounter implements an LRU cache for tracking the
// counter values of nonces.
type NonceCounter struct {
	// m maps nonce to list elements
	m map[string]*list.Element

	// ll orders most recently used elements to the front
	ll *list.List

	// cap specifies the capacity of this cache
	cap int
}

// NewNonceCounter returns a new NonceCounter with
// the specified capacity
func NewNonceCounter(cap int) *NonceCounter {
	if cap < 1 {
		cap = 1
	}
	return &NonceCounter{
		m:   make(map[string]*list.Element),
		ll:  list.New(),
		cap: cap,
	}
}

// Next increments the counter for nonce and returns
// the new counter value
func (nc *NonceCounter) Next(nonce string) int {
	p, ok := nc.m[nonce]
	if ok {
		nc.ll.MoveToFront(p)
		v := p.Value.(item)
		v.n = v.n + 1
		return v.n
	}

	if len(nc.m) == nc.cap {
		p = nc.ll.Back()
		nc.ll.Remove(p)
		delete(nc.m, p.Value.(item).k)
	}

	v := item{nonce, 1}
	p = nc.ll.PushFront(v)
	nc.m[nonce] = p

	return v.n
}

type item struct {
	k string
	n int
}
