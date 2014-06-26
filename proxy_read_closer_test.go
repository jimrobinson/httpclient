package httpclient

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

func TestMemFileReadCloser(t *testing.T) {
	threshold := 1024

	tests := [][]byte{
		make([]byte, threshold/2),
		make([]byte, threshold-1),
		make([]byte, threshold),
		make([]byte, threshold+1),
		make([]byte, threshold*2),
	}

	for _, b := range tests {
		for i := 0; i < len(b); i++ {
			b[i] = byte(i % 127)
		}
	}

	for i, b := range tests {

		mfrc := NewMemFileReadCloser("", threshold)

		total := 0
		r := bytes.NewBuffer(b)
		for {
			l := make([]byte, 256)

			n1, err := r.Read(l)
			if err != nil {
				if err != io.EOF {
					t.Fatalf("[%d]: %v", i, err)
				}
				err = nil
				mfrc.Close()
				break
			}

			n2, err := mfrc.Write(l[0:n1])
			if err != nil {
				t.Fatalf("[%d]: %v", i, err)
			}

			if n1 != n2 {
				t.Fatalf("[%d]: read %d bytes, wrote %d bytes", i, n1, n2)
			}

			total += n2
			switch {
			case total < threshold:
				if mfrc.fh != nil {
					t.Errorf("[%d]: %d of %d threshold bytes written, but filehandle is open", i, total, threshold)
				}
			case total == threshold:
				if mfrc.fh != nil {
					t.Errorf("[%d]: %d of %d threshold bytes written, but filehandle is open", i, total, threshold)
				}
			case total > threshold:
				if mfrc.fh == nil {
					t.Errorf("[%d]: %d bytes over the %d threshold written, but filehandle is not open", i, total-threshold, threshold)
				}
			}
		}

		if total != len(b) {
			t.Fatalf("[%d]: %d bytes written instead of the expected %d bytes", i, total, len(b))
		}

		rc, err := mfrc.ReadCloser()
		if err != nil {
			t.Fatalf("[%d]: %v", i, err)
		}

		rb, err := ioutil.ReadAll(rc)
		if err != nil {
			t.Fatalf("[%d]: %v", i, err)
		}

		if bytes.Compare(b, rb) != 0 {
			t.Fatalf("[%d]: bytes written and read do not match:\n%v\n%v", i, b, rb)
		}

		err = rc.Close()
		if err != nil {
			t.Fatalf("[%d]: %v", i, err)
		}
	}
}

func TestInternalReadCloserMemory(t *testing.T) {

	buf := make([]byte, 127)
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i)
	}

	rc := readCloser{
		buf: bytes.NewBuffer(buf),
		fh:  nil,
	}

	for i := 0; i < len(buf); i++ {
		b := make([]byte, 1)
		n, err := rc.Read(b)
		if err != nil {
			if err != io.EOF {
				t.Fatalf("error reading from memory-based readCloser: %v", err)
			}
			if i != len(buf) {
				t.Fatalf("got EOF after %d bytes instead of the expected %d", i, len(buf))
			}
		}

		if n != len(b) {
			t.Errorf("expected 1 byte read from rc at pos %d, got %d", len(b), n)
			break
		}

		if b[0] != buf[i] {
			t.Errorf("expected %q at position %d: %q", buf[i], i, buf[0])
		}
	}

	err := rc.Close()
	if err != nil {
		t.Fatalf("error closing memory-based readCloser: %v", err)
	}
}

func TestInternalReadCloserFile(t *testing.T) {
	buf := make([]byte, 127)
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i)
	}

	fh, err := ioutil.TempFile("", "TestInternalReadCloserFile")
	if err != nil {
		t.Fatal(err)
	}

	n, err := fh.Write(buf)
	if err != nil {
		t.Fatalf("error writing test bytes to %s: %v", fh.Name(), err)
	}
	if n != len(buf) {
		t.Fatalf("expected %d bytes written, got back %d bytes written", len(buf), n)
	}

	err = fh.Close()
	if err != nil {
		t.Fatal(err)
	}

	fh, err = os.Open(fh.Name())
	if err != nil {
		t.Fatal(err)
	}

	rc := readCloser{
		buf: nil,
		fh:  fh,
	}

	for i := 0; i < len(buf); i++ {
		b := make([]byte, 1)
		n, err := rc.Read(b)
		if err != nil {
			if err != io.EOF {
				t.Fatalf("error reading from file-based readCloser: %v", err)
			}
			if i != len(buf) {
				t.Fatalf("got EOF after %d bytes instead of the expected %d", i, len(buf))
			}
		}

		if n != len(b) {
			t.Errorf("expected 1 byte read from rc at pos %d, got %d", len(b), n)
			break
		}

		if b[0] != buf[i] {
			t.Errorf("expected %q at position %d: %q", buf[i], i, buf[0])
		}
	}

	err = rc.Close()
	if err != nil {
		t.Fatalf("error closing file-based readCloser: %v", err)
	}

	_, err = os.Stat(fh.Name())
	if err == nil {
		t.Fatal("expected no such file or directory error")

	}
	if !strings.HasSuffix(err.Error(), ": no such file or directory") {
		t.Fatalf("expected no such file or directory error: %v", err)
	}
}
