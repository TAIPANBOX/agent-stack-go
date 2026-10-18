package event

import (
	"bytes"
	"encoding"
	"hash"
	"io"
)

// lineScanner reads a stream once, hashing every byte it reads with sum and
// calling emit for each newline-terminated line, in order.
//
// emit runs at the line's LF, when sum holds exactly the bytes through that LF,
// so a caller that needs a digest at a line boundary takes it there. Bytes after
// the last LF are hashed as they are read; settle undoes that, which a caller
// that goes on hashing from the last boundary must do before it writes again.
// A line longer than maxLen is emitted as long, with no bytes: its content is
// hashed all the same, because the prefix covers it.
type lineScanner struct {
	sum     hash.Hash
	maxLen  int
	keep    bool   // marshal sum's state at every LF, so settle can restore it
	cur     []byte // the line in progress, at most maxLen bytes
	long    bool   // the line in progress is longer than maxLen
	pos     int64  // bytes consumed
	off     int64  // offset just after the last LF
	lines   int    // LFs consumed
	last    []byte // sum's state at off, when keep is set; nil for a fresh sum
	partial bool   // bytes after the last LF were hashed
}

// newLineScanner starts a scan at offset off, where sum holds the bytes before it
// and last (nil for none) is their marshalled state.
func newLineScanner(sum hash.Hash, off int64, last []byte, lines, maxLen int, keep bool) *lineScanner {
	return &lineScanner{sum: sum, maxLen: maxLen, keep: keep, pos: off, off: off, last: last, lines: lines}
}

func (s *lineScanner) add(b []byte) {
	if s.long {
		return
	}
	if len(s.cur)+len(b) > s.maxLen {
		s.long = true
		s.cur = nil
		return
	}
	s.cur = append(s.cur, b...)
}

// marshal is sum's state. A SHA-256 digest cannot fail to marshal, so the error
// is not checked.
func (s *lineScanner) marshal() []byte {
	b, _ := s.sum.(encoding.BinaryMarshaler).MarshalBinary()
	return b
}

// run reads r to its end. It returns the first error from r or from emit.
func (s *lineScanner) run(r io.Reader, emit func(line []byte, long bool, end int64) error) error {
	buf := make([]byte, 64<<10)
	for {
		n, rerr := r.Read(buf)
		p := buf[:n]
		for len(p) > 0 {
			i := bytes.IndexByte(p, '\n')
			if i < 0 {
				s.sum.Write(p)
				s.pos += int64(len(p))
				s.add(p)
				s.partial = true
				break
			}
			seg := p[:i+1]
			s.sum.Write(seg)
			s.pos += int64(len(seg))
			s.add(seg[:i])
			s.off = s.pos
			s.partial = false
			if s.keep {
				s.last = s.marshal()
			}
			line, long := s.cur, s.long
			s.cur, s.long = nil, false
			s.lines++
			if err := emit(line, long, s.off); err != nil {
				return err
			}
			p = p[i+1:]
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

// settle restores sum to the state at off, undoing the bytes after the last LF.
func (s *lineScanner) settle() error {
	if !s.partial {
		return nil
	}
	s.partial = false
	if s.last == nil {
		s.sum.Reset()
		return nil
	}
	return s.sum.(encoding.BinaryUnmarshaler).UnmarshalBinary(s.last)
}
