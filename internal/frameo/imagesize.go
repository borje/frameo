// SPDX-License-Identifier: GPL-3.0-or-later

package frameo

// imageSize reads a photo's pixel dimensions out of its own header.
//
// It exists because the frame never states them. A reply describes a photo by
// byte count and extension and nothing else, the listing describes it by less
// than that, and the bound a fetch carries picks between stored copies rather
// than describing either of them -- so the bytes are the only place the answer
// is written down. Both formats a frame has been seen to return are covered:
// WebP, which is what it re-encodes a photo into, and JPEG.
//
// Zero and zero mean the format was not recognised, or its header was too
// short or too odd to trust. That is an ordinary answer rather than an error.
// A photo whose dimensions cannot be read has still arrived whole, and
// refusing it over a parser that exists for one line of output would throw
// away a perfectly good file. Nothing here is load-bearing for correctness.
func imageSize(data []byte) (w, h int) {
	switch {
	case len(data) >= 12 && string(data[0:4]) == "RIFF" && string(data[8:12]) == "WEBP":
		return webpSize(data[12:])
	case len(data) >= 2 && data[0] == 0xff && data[1] == 0xd8:
		return jpegSize(data[2:])
	}
	return 0, 0
}

// webpSize reads the canvas size out of a RIFF/WEBP container, given the bytes
// that follow the container header.
//
// Only the first chunk is read. A container that has a VP8X puts it first, and
// one that has not holds exactly a single image chunk, so a later chunk cannot
// be the one that carries the size. All three forms are worth handling: of the
// photos fetched off a real frame, a third arrived as a bare VP8 keyframe --
// which is what a preview comes back as -- and the rest as VP8X carrying an
// embedded colour profile.
func webpSize(b []byte) (w, h int) {
	if len(b) < 8 {
		return 0, 0
	}
	tag, payload := string(b[0:4]), b[8:]

	switch tag {
	case "VP8X":
		// Four bytes of flags, then the canvas dimensions as 24-bit
		// little-endian counts held one below the real size.
		if len(payload) < 10 {
			return 0, 0
		}
		w = int(payload[4]) | int(payload[5])<<8 | int(payload[6])<<16
		h = int(payload[7]) | int(payload[8])<<8 | int(payload[9])<<16
		return w + 1, h + 1

	case "VP8 ":
		// A three-byte frame tag, then a start code that only a keyframe
		// carries. Refusing a chunk without it matters: an interframe cannot
		// be the whole of a still, and reading dimensions from where the start
		// code should have been is how a parser invents them.
		if len(payload) < 10 || payload[3] != 0x9d || payload[4] != 0x01 || payload[5] != 0x2a {
			return 0, 0
		}
		w = (int(payload[6]) | int(payload[7])<<8) & 0x3fff
		h = (int(payload[8]) | int(payload[9])<<8) & 0x3fff
		if w == 0 || h == 0 {
			return 0, 0
		}
		return w, h

	case "VP8L":
		// A signature byte, then both dimensions packed into one 32-bit
		// little-endian word as 14 bits each, again one below the real size.
		if len(payload) < 5 || payload[0] != 0x2f {
			return 0, 0
		}
		bits := uint32(payload[1]) | uint32(payload[2])<<8 | uint32(payload[3])<<16 | uint32(payload[4])<<24
		return int(bits&0x3fff) + 1, int((bits>>14)&0x3fff) + 1
	}
	return 0, 0
}

// jpegSize walks the segment chain to the frame header, given the bytes that
// follow the start-of-image marker.
//
// It has to walk rather than read a fixed offset: every JPEG a frame has
// returned puts an ICC profile in an APP2 segment ahead of the frame header,
// and some a JFIF APP0 ahead of that. Every marker from C0 to CF is a frame
// header except C4, C8 and CC, which share the range but describe tables and
// arithmetic coding. C2 has to be among the ones that count, because the
// frame's own JPEGs come back progressive.
func jpegSize(b []byte) (w, h int) {
	for i := 0; i < len(b); {
		// Markers are introduced by one or more fill bytes. Anything else
		// here means the walk has lost its place, and guessing from a lost
		// place is worse than saying nothing.
		if b[i] != 0xff {
			return 0, 0
		}
		for i < len(b) && b[i] == 0xff {
			i++
		}
		if i >= len(b) {
			return 0, 0
		}
		marker := b[i]
		i++

		// These stand alone and carry no length to step over.
		if marker == 0x01 || (marker >= 0xd0 && marker <= 0xd9) {
			continue
		}
		if i+2 > len(b) {
			return 0, 0
		}
		// The length counts itself. Anything below two would leave the offset
		// where it was and walk this loop for ever.
		length := int(b[i])<<8 | int(b[i+1])
		if length < 2 {
			return 0, 0
		}
		// The entropy-coded data starts here and there are no more segments to
		// step over, so a frame header not seen by now is not coming.
		if marker == 0xda {
			return 0, 0
		}
		if isStartOfFrame(marker) {
			// One byte of sample precision, then the dimensions, height first.
			if i+7 > len(b) {
				return 0, 0
			}
			h = int(b[i+3])<<8 | int(b[i+4])
			w = int(b[i+5])<<8 | int(b[i+6])
			// A height of zero is a real encoding: it says the true one
			// arrives later, in a DNL marker after the scan. Nothing here
			// reads that far, so the honest answer is that we do not know.
			if w == 0 || h == 0 {
				return 0, 0
			}
			return w, h
		}
		i += length
	}
	return 0, 0
}

// isStartOfFrame reports whether the marker introduces a frame header, which
// is the segment that states the dimensions.
func isStartOfFrame(marker byte) bool {
	if marker < 0xc0 || marker > 0xcf {
		return false
	}
	// The three exceptions sit inside the range but describe Huffman tables,
	// arithmetic coding conditioning and a restart interval instead.
	return marker != 0xc4 && marker != 0xc8 && marker != 0xcc
}
