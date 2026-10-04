package media

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

var (
	errTruncated = errors.New("media: unexpected end of file")
	errTooLarge  = errors.New("media: structure exceeds size limit")
)

// source is a random-access view of the data being probed. Knowing the size
// up front lets every read be validated against the real data length before
// anything is allocated, so corrupt length fields cannot cause huge buffers.
type source struct {
	r    io.ReaderAt
	size int64
}

func newByteSource(b []byte) *source {
	return &source{r: bytes.NewReader(b), size: int64(len(b))}
}

// read returns exactly n bytes at off. Requests outside the data or larger
// than maxTagSize fail without allocating.
func (s *source) read(off, n int64) ([]byte, error) {
	switch {
	case off < 0 || n < 0 || off > s.size || n > s.size-off:
		return nil, errTruncated
	case n > maxTagSize:
		return nil, errTooLarge
	}
	b := make([]byte, n)
	if m, err := s.r.ReadAt(b, off); m < len(b) {
		if err == nil || err == io.EOF {
			err = errTruncated
		}
		return nil, err
	}
	return b, nil
}

// peek returns up to n bytes at off: fewer near the end of the data, nil when
// off is out of range or the read fails.
func (s *source) peek(off, n int64) []byte {
	if off < 0 || off >= s.size || n <= 0 {
		return nil
	}
	b, err := s.read(off, min(n, s.size-off))
	if err != nil {
		return nil
	}
	return b
}

// section returns a source limited to [off, off+n), clamped to the data.
func (s *source) section(off, n int64) *source {
	off = max(0, min(off, s.size))
	n = max(0, min(n, s.size-off))
	return &source{r: io.NewSectionReader(s.r, off, n), size: n}
}

// cursor decodes fixed-layout fields from a byte slice. Reading past the end
// returns zero values and marks the cursor bad, so a parser can decode a
// whole structure and check bad once instead of bounds-checking every field.
type cursor struct {
	b   []byte
	bad bool
}

// take consumes and returns the next n bytes (nil once the cursor is bad).
func (c *cursor) take(n int) []byte {
	if c.bad || n < 0 || n > len(c.b) {
		c.bad = true
		c.b = nil
		return nil
	}
	v := c.b[:n:n]
	c.b = c.b[n:]
	return v
}

func (c *cursor) skip(n int) { c.take(n) }

// len reports how many bytes remain.
func (c *cursor) len() int { return len(c.b) }

func (c *cursor) u8() uint8 {
	if b := c.take(1); len(b) == 1 {
		return b[0]
	}
	return 0
}

func (c *cursor) u16() uint16 {
	if b := c.take(2); len(b) == 2 {
		return binary.BigEndian.Uint16(b)
	}
	return 0
}

func (c *cursor) u24() uint32 {
	if b := c.take(3); len(b) == 3 {
		return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
	}
	return 0
}

func (c *cursor) u32() uint32 {
	if b := c.take(4); len(b) == 4 {
		return binary.BigEndian.Uint32(b)
	}
	return 0
}

func (c *cursor) u64() uint64 {
	if b := c.take(8); len(b) == 8 {
		return binary.BigEndian.Uint64(b)
	}
	return 0
}

func (c *cursor) u16le() uint16 {
	if b := c.take(2); len(b) == 2 {
		return binary.LittleEndian.Uint16(b)
	}
	return 0
}

func (c *cursor) u32le() uint32 {
	if b := c.take(4); len(b) == 4 {
		return binary.LittleEndian.Uint32(b)
	}
	return 0
}

func (c *cursor) u64le() uint64 {
	if b := c.take(8); len(b) == 8 {
		return binary.LittleEndian.Uint64(b)
	}
	return 0
}
