// SPDX-License-Identifier: GPL-3.0-or-later

package frameotest

import "encoding/binary"

// Photos for tests to hand around, in the formats a real frame deals in.
//
// They carry real headers rather than bytes that merely start the right way,
// because the client measures a downloaded photo by parsing it: a fixture that
// only looked like a photo would leave that measurement untested. Everything
// past the header is filler, so these are not decodable images -- nothing in
// this project decodes one -- and size is the total length in bytes, padded out
// so a test can also exercise what a large photo meets on the way.

// WebP builds a lossy WebP: a bare VP8 keyframe, which is the form a real
// frame returns a preview in.
func WebP(w, h, size int) []byte {
	return riff(chunk("VP8 ", pad(keyframe(w, h), size-webpOverhead)))
}

// WebPExtended builds a WebP in its extended form: a VP8X chunk stating the
// canvas size, then the image itself. It is the form a real frame returns an
// original in, where the extension carries a colour profile.
func WebPExtended(w, h, size int) []byte {
	canvas := []byte{0x08, 0x00, 0x00, 0x00} // flags: an ICC profile is present
	canvas = append(canvas, byte(w-1), byte((w-1)>>8), byte((w-1)>>16))
	canvas = append(canvas, byte(h-1), byte((h-1)>>8), byte((h-1)>>16))
	image := pad(keyframe(w, h), size-webpOverhead-len(canvas)-chunkHeader)
	return riff(append(chunk("VP8X", canvas), chunk("VP8 ", image)...))
}

// WebPLossless builds a WebP in its lossless form. No frame has been seen to
// return one, which is why it is worth having: a photo in a form nobody
// expected should still measure rather than come back as unknown.
func WebPLossless(w, h, size int) []byte {
	bits := uint32(w-1) | uint32(h-1)<<14
	payload := binary.LittleEndian.AppendUint32([]byte{0x2f}, bits)
	return riff(chunk("VP8L", pad(payload, size-webpOverhead)))
}

// JPEG builds a baseline JPEG, with a JFIF segment and then an ICC profile
// ahead of the frame header -- the shape every JPEG a frame has returned has,
// and the reason the dimensions cannot be read at a fixed offset.
func JPEG(w, h, size int) []byte { return jpeg(w, h, size, 0xc0) }

// ProgressiveJPEG builds the other shape the frame's own JPEGs come back in.
// Its frame header is a different marker, sharing a range with three markers
// that state no dimensions at all.
func ProgressiveJPEG(w, h, size int) []byte { return jpeg(w, h, size, 0xc2) }

const (
	// chunkHeader is a RIFF chunk's four-byte tag and four-byte length.
	chunkHeader = 8
	// webpOverhead is the container header and one chunk header, which is what
	// a payload has to make up the rest of a file after.
	webpOverhead = 12 + chunkHeader
)

// keyframe is the VP8 header that states the dimensions.
func keyframe(w, h int) []byte {
	return []byte{
		0xd0, 0x9a, 0x01, // frame tag, low bit clear for a keyframe
		0x9d, 0x01, 0x2a, // the start code only a keyframe carries
		byte(w), byte(w >> 8),
		byte(h), byte(h >> 8),
	}
}

func jpeg(w, h, size int, startOfFrame byte) []byte {
	b := []byte{0xff, 0xd8}
	b = append(b, segment(0xe0, append([]byte("JFIF\x00"), 0x01, 0x01, 0x00, 0, 1, 0, 1, 0, 0))...)
	b = append(b, segment(0xe2, append([]byte("ICC_PROFILE\x00"), make([]byte, 20)...))...)
	b = append(b, segment(startOfFrame, []byte{
		0x08,                  // sample precision
		byte(h >> 8), byte(h), // height first, which is the easy one to invert
		byte(w >> 8), byte(w), //
		0x01,             // one component
		0x01, 0x11, 0x00, // its id, sampling factors and quantisation table
	})...)
	b = append(b, segment(0xda, []byte{0x01, 0x01, 0x00, 0x00, 0x3f, 0x00})...)
	// The entropy-coded data, which nothing here reads, then the end marker
	// checkWhole looks for.
	b = pad(b, size-2)
	return append(b, 0xff, 0xd9)
}

// segment wraps a payload in a marker and the length that counts itself.
func segment(marker byte, payload []byte) []byte {
	b := []byte{0xff, marker, byte((len(payload) + 2) >> 8), byte(len(payload) + 2)}
	return append(b, payload...)
}

// chunk wraps a payload in a RIFF chunk header.
func chunk(tag string, payload []byte) []byte {
	b := binary.LittleEndian.AppendUint32([]byte(tag), uint32(len(payload)))
	return append(b, payload...)
}

// riff wraps chunks in a WEBP container.
func riff(body []byte) []byte {
	b := binary.LittleEndian.AppendUint32([]byte("RIFF"), uint32(len(body)+4))
	return append(append(b, "WEBP"...), body...)
}

// pad grows b to n bytes with filler that no parser here will mistake for a
// marker or a chunk tag. A b already that long is left as it is, so a size too
// small to hold the header simply gives the header.
func pad(b []byte, n int) []byte {
	for i := len(b); i < n; i++ {
		b = append(b, byte(i%251+1))
	}
	return b
}
