package httpclient

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

type ProxyReadCloser interface {
	Write(p []byte) (n int, err error)
	Close() (err error)
	ReadCloser() (rc io.ReadCloser, err error)
}

type MemFileReadCloser struct {
	limit int
	buf   *bytes.Buffer
	fh    *os.File
	dir   string
	used  bool
}

func NewMemFileReadCloser(dir string, limit int) *MemFileReadCloser {
	return &MemFileReadCloser{
		limit: limit,
		buf:   &bytes.Buffer{},
		fh:    nil,
		dir:   dir,
		used:  false,
	}
}

func (w *MemFileReadCloser) Write(p []byte) (n int, err error) {
	if w.fh != nil {
		return w.fh.Write(p)
	}

	n, err = w.buf.Write(p)
	if err != nil || w.limit < 0 || w.buf.Len() < w.limit {
		return n, err
	}

	// buf length has reached limit, write to temp file
	w.fh, err = ioutil.TempFile(w.dir, "MemFileReadCloser")
	if err != nil {
		return n, err
	}

	_, err = w.fh.Write(w.buf.Bytes())
	if err == nil {
		w.buf.Reset()
	} else {
		w.fh.Close()
		os.Remove(w.fh.Name())
		w.fh = nil
	}

	return n, err
}

func (w *MemFileReadCloser) Close() (err error) {
	if w.fh != nil {
		err = w.fh.Close()
	}
	return err
}

func (w *MemFileReadCloser) ReadCloser() (rc io.ReadCloser, err error) {
	if w.used {
		err = fmt.Errorf("ReadCloser has already been used")
		return nil, err
	} else {
		w.used = true
	}

	var fh *os.File
	if w.fh != nil {
		fh, err = os.Open(w.fh.Name())
	}

	rc = &readCloser{
		buf: w.buf,
		fh:  fh,
	}

	return rc, err
}

type readCloser struct {
	buf *bytes.Buffer
	fh  *os.File
}

func (rc *readCloser) Read(p []byte) (n int, err error) {
	if rc.fh != nil {
		return rc.fh.Read(p)
	}
	return rc.buf.Read(p)
}

func (rc *readCloser) Close() (err error) {
	if rc.fh != nil {
		e1 := rc.fh.Close()
		e2 := os.Remove(rc.fh.Name())
		if e1 != nil {
			err = e1
		} else {
			err = e2
		}
	}
	return err
}
