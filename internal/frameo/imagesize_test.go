package frameo

import (
	"bytes"
	"math/rand/v2"
	"testing"

	"frameo/internal/frameo/frameotest"
)

// TestImageSizeReadsEveryShapeAFrameSends covers each form a photo has been
// seen to arrive in. The lossy WebP is what a preview comes back as and the
// extended one what an original comes back as, so a parser that handled only
// the second would fail on exactly the copies -size preview exists to fetch.
func TestImageSizeReadsEveryShapeAFrameSends(t *testing.T) {
	for _, c := range []struct {
		name string
		w, h int
		data []byte
	}{
		{"webp lossy landscape", 570, 380, frameotest.WebP(570, 380, 4000)},
		{"webp lossy portrait", 380, 570, frameotest.WebP(380, 570, 4000)},
		{"webp extended", 2880, 1920, frameotest.WebPExtended(2880, 1920, 9000)},
		{"webp extended portrait", 1920, 2880, frameotest.WebPExtended(1920, 2880, 9000)},
		{"webp lossless", 1024, 768, frameotest.WebPLossless(1024, 768, 4000)},
		{"jpeg baseline", 1067, 712, frameotest.JPEG(1067, 712, 4000)},
		{"jpeg progressive", 1067, 1600, frameotest.ProgressiveJPEG(1067, 1600, 4000)},
	} {
		w, h := imageSize(c.data)
		if w != c.w || h != c.h {
			t.Errorf("%s: imageSize = %dx%d, want %dx%d", c.name, w, h, c.w, c.h)
		}
	}
}

// TestImageSizeRefusesWhatItCannotRead is the policy: a header this parser
// cannot follow answers that it does not know, and never a guess. Every case
// here is one where a plausible shortcut would have produced a number.
func TestImageSizeRefusesWhatItCannotRead(t *testing.T) {
	good := frameotest.WebP(570, 380, 200)
	extended := frameotest.WebPExtended(2880, 1920, 200)
	lossless := frameotest.WebPLossless(1024, 768, 200)
	baseline := frameotest.JPEG(1067, 712, 200)

	unknownChunk := append([]byte(nil), good...)
	copy(unknownChunk[12:16], "ANIM")

	noStartCode := append([]byte(nil), good...)
	noStartCode[23] = 0x00 // the 0x9d that says this is a keyframe

	noSignature := append([]byte(nil), lossless...)
	noSignature[20] = 0x00 // the 0x2f a lossless stream opens with

	zeroHeight := frameotest.JPEG(1067, 0, 200)

	for _, c := range []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"one byte", []byte{0xff}},
		{"not an image", []byte("this is a text file, not a photo at all")},
		{"png", []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x04\x00\x00\x00\x03\x00")},
		{"riff that is not a webp", []byte("RIFF\x00\x00\x00\x00AVI LIST")},
		{"webp truncated in the container", good[:10]},
		{"webp truncated in the chunk header", good[:16]},
		{"webp truncated in the payload", good[:22]},
		{"webp chunk this parser does not know", unknownChunk},
		{"webp lossy without its start code", noStartCode},
		{"webp lossless without its signature", noSignature},
		{"webp extended truncated in the canvas", extended[:26]},
		{"jpeg with nothing after the marker", []byte{0xff, 0xd8}},
		{"jpeg truncated before the frame header", baseline[:30]},
		{"jpeg that reaches the scan with no frame header", noFrameHeader()},
		{"jpeg with a segment length of zero", badSegmentLength()},
		{"jpeg stating a height of zero", zeroHeight},
	} {
		if w, h := imageSize(c.data); w != 0 || h != 0 {
			t.Errorf("%s: imageSize = %dx%d, want it to say it does not know", c.name, w, h)
		}
	}
}

// noFrameHeader is a JPEG whose scan begins with no frame header before it, so
// the dimensions are never stated.
func noFrameHeader() []byte {
	return []byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x04, 0x00, 0x00, 0xff, 0xda, 0x00, 0x08, 1, 1, 0, 0, 0x3f, 0}
}

// badSegmentLength is the one malformation that could hang the walk rather
// than end it: a length that does not advance past itself.
func badSegmentLength() []byte {
	return []byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x00, 0x00, 0x00, 0xff, 0xc0, 0x00, 0x0b, 8, 0, 10, 0, 10, 1, 1, 0x11, 0}
}

// TestImageSizeSurvivesArbitraryBytes mutates good photos at random, which is
// where the arithmetic on lengths and offsets gets exercised far past what a
// list of cases reaches. The answer is only ever two positive numbers or none.
func TestImageSizeSurvivesArbitraryBytes(t *testing.T) {
	seeds := [][]byte{
		frameotest.WebP(570, 380, 600),
		frameotest.WebPExtended(2880, 1920, 600),
		frameotest.WebPLossless(1024, 768, 600),
		frameotest.JPEG(1067, 712, 600),
		frameotest.ProgressiveJPEG(1067, 1600, 600),
	}
	rnd := rand.New(rand.NewPCG(7, 1))
	for i := 0; i < 20000; i++ {
		seed := seeds[rnd.IntN(len(seeds))]
		data := bytes.Clone(seed)
		if n := rnd.IntN(len(data)); n > 0 {
			data = data[:n]
		}
		for j := 0; j < 1+rnd.IntN(4); j++ {
			data[rnd.IntN(len(data))] = byte(rnd.UintN(256))
		}
		w, h := imageSize(data)
		if (w == 0) != (h == 0) || w < 0 || h < 0 {
			t.Fatalf("imageSize = %dx%d on %x", w, h, data[:min(len(data), 32)])
		}
	}
}
