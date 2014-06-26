package httpclient

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

// ProxyReadCloser defines an interface that holds a copy of bytes
// written to it, returnable as a new io.ReadCloser.  Paired with an
// io.MultiWriter, it's possible to clone an http.Request Body, or
// to process the body without losing access to the data if a request
// Body is a streaming source.
type ProxyReadCloser interface {
	Write(p []byte) (n int, err error)
	Close() (err error)
	ReadCloser() (rc io.ReadCloser, err error)
}

// MemFileReadCloser implements ProxyReadCloser, keeping its copy
// buffer in memory unless a limit is reached, then falling back to
// copying the bytes
// to a temporary file on disk.
type MemFileReadCloser struct {
	limit int
	buf   *bytes.Buffer
	fh    *os.File
	dir   string
	used  bool
}

// NewMemFileReadCloser returns a MemFileReadCLoser that will write
// a temporary file to dir if more than limit bytes are written to
// it.  If the specified dir is an empty string,
// the OS temporary directory will be used.
func NewMemFileReadCloser(dir string, limit int) *MemFileReadCloser {
	return &MemFileReadCloser{
		limit: limit,
		buf:   &bytes.Buffer{},
		fh:    nil,
		dir:   dir,
		used:  false,
	}
}

// Write copies bytes from p, returning the number of bytes written
// and any error encountered.
func (w *MemFileReadCloser) Write(p []byte) (n int, err error) {
	if w.fh != nil {
		return w.fh.Write(p)
	}

	n, err = w.buf.Write(p)
	if err != nil || w.limit < 0 || w.buf.Len() <= w.limit {
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

// Close indicates that the caller has finished writing bytes to the
// MemFileReadCloser.
func (w *MemFileReadCloser) Close() (err error) {
	if w.fh != nil {
		err = w.fh.Close()
	}
	return err
}

// ReadCloser returns an io.ReadCloser
// that will return any bytes written
// to it.  Only one call to ReadCloser is
// allowed.
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

// readCloser implements io.ReadCloser, selecting its bytes from
// either fh or buf, depending on what is available.
type readCloser struct {
	buf *bytes.Buffer
	fh  *os.File
}

// Read returns bytes from its filehandle if available, otherwise it
// returns them from its in-memory buffer.
func (rc *readCloser) Read(p []byte) (n int, err error) {
	if rc.fh != nil {
		return rc.fh.Read(p)
	}
	return rc.buf.Read(p)
}

// Close indicates that the caller has finished reading bytes.  If
// the underlying filehandle has been allocated, it will be closed
// and the file unlinked.
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
