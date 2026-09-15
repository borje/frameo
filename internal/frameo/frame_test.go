// SPDX-License-Identifier: GPL-3.0-or-later

package frameo

import (
	"bytes"
	"encoding/hex"
	"math/rand/v2"
	"testing"

	"github.com/borje/unframeo/internal/frameo/pb"
	"google.golang.org/protobuf/proto"
)

func TestEncodeFrameGolden(t *testing.T) {
	body, err := encodeFrame(TypeGetInfo, &pb.GetInfo{})
	if err != nil {
		t.Fatal(err)
	}
	// An empty request is just the two header words: the constant prefix and
	// the message number.
	if got, want := hex.EncodeToString(body), "0000001200000001"; got != want {
		t.Errorf("GetInfo = %s, want %s", got, want)
	}
}

func TestFrameRoundTrip(t *testing.T) {
	body := encodeFrameBytes(TypeMedia, []byte{1, 2, 3, 4})
	f, err := decodeFrame(body)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != TypeMedia {
		t.Errorf("type = %d, want %d", f.Type, TypeMedia)
	}
	if !bytes.Equal(f.Payload, []byte{1, 2, 3, 4}) {
		t.Errorf("payload = %v", f.Payload)
	}
	if got := f.String(); got != "Media(4), 4 bytes" {
		t.Errorf("String() = %q", got)
	}
}

func TestDecodeFrameRejectsBadInput(t *testing.T) {
	if _, err := decodeFrame([]byte{1, 2, 3}); err == nil {
		t.Error("want an error for a short message")
	}
	bad := encodeFrameBytes(TypeMedia, nil)
	bad[3] = 0x99
	if _, err := decodeFrame(bad); err == nil {
		t.Error("want an error for a wrong prefix")
	}
}

func TestSplitLeavesSmallMessagesAlone(t *testing.T) {
	for _, size := range []int{0, 1, MaxMessage - 1, MaxMessage} {
		msg := bytes.Repeat([]byte{0x5a}, size)
		parts, err := split(msg, 1)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if len(parts) != 1 {
			t.Errorf("size %d split into %d parts, want 1", size, len(parts))
		}
		if !bytes.Equal(parts[0], msg) {
			t.Errorf("size %d was modified", size)
		}
	}
}

func TestSplitAndReassemble(t *testing.T) {
	sizes := []int{MaxMessage + 1, 2 * chunkSize, 2*chunkSize + 1, 1 << 20}
	for _, size := range sizes {
		msg := make([]byte, size)
		rnd := rand.New(rand.NewPCG(1, uint64(size)))
		for i := range msg {
			msg[i] = byte(rnd.UintN(256))
		}

		parts, err := split(msg, 42)
		if err != nil {
			t.Fatalf("size %d: split: %v", size, err)
		}
		if len(parts) < 2 {
			t.Fatalf("size %d produced %d parts", size, len(parts))
		}

		r := newReassembler(0)
		var got []byte
		for i, part := range parts {
			if len(part) > MaxMessage {
				t.Fatalf("size %d: part %d is %d bytes, over the limit", size, i, len(part))
			}
			f, err := decodeFrame(part)
			if err != nil {
				t.Fatal(err)
			}
			if f.Type != TypeMultiPartMessage {
				t.Fatalf("part %d has type %d", i, f.Type)
			}
			out, err := r.add(f.Payload)
			if err != nil {
				t.Fatalf("size %d: part %d: %v", size, i, err)
			}
			if out != nil {
				got = out
			}
		}
		if !bytes.Equal(got, msg) {
			t.Errorf("size %d did not survive the round trip", size)
		}
		if r.pending() != 0 {
			t.Errorf("size %d left %d messages partly received", size, r.pending())
		}
	}
}

func TestReassembleOutOfOrder(t *testing.T) {
	msg := bytes.Repeat([]byte{0xc3}, 5*chunkSize)
	for i := range msg {
		msg[i] = byte(i)
	}
	parts, err := split(msg, 7)
	if err != nil {
		t.Fatal(err)
	}

	order := []int{4, 0, 3, 1, 2}
	r := newReassembler(0)
	var got []byte
	for _, i := range order {
		f, _ := decodeFrame(parts[i])
		out, err := r.add(f.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if out != nil {
			got = out
		}
	}
	if !bytes.Equal(got, msg) {
		t.Error("out-of-order parts did not reassemble correctly")
	}
}

func TestReassembleInterleavedMessages(t *testing.T) {
	a := bytes.Repeat([]byte{0xaa}, 3*chunkSize)
	b := bytes.Repeat([]byte{0xbb}, 3*chunkSize)
	pa, _ := split(a, 100)
	pb2, _ := split(b, 200)

	r := newReassembler(0)
	var gotA, gotB []byte
	for i := range pa {
		fa, _ := decodeFrame(pa[i])
		fb, _ := decodeFrame(pb2[i])
		if out, err := r.add(fa.Payload); err != nil {
			t.Fatal(err)
		} else if out != nil {
			gotA = out
		}
		if out, err := r.add(fb.Payload); err != nil {
			t.Fatal(err)
		} else if out != nil {
			gotB = out
		}
	}
	if !bytes.Equal(gotA, a) || !bytes.Equal(gotB, b) {
		t.Error("interleaved messages were not kept apart")
	}
}

func TestReassembleIgnoresRepeatedPart(t *testing.T) {
	msg := bytes.Repeat([]byte{0x11}, 2*chunkSize)
	parts, _ := split(msg, 5)

	r := newReassembler(0)
	f0, _ := decodeFrame(parts[0])
	if _, err := r.add(f0.Payload); err != nil {
		t.Fatal(err)
	}
	// A repeat must not be counted twice, or the message would look complete
	// while a part is still missing.
	if out, err := r.add(f0.Payload); err != nil || out != nil {
		t.Fatalf("repeated part returned %v, %v", out, err)
	}
	f1, _ := decodeFrame(parts[1])
	out, err := r.add(f1.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, msg) {
		t.Error("message did not complete after the missing part arrived")
	}
}

func TestReassembleRejectsBadParts(t *testing.T) {
	r := newReassembler(0)

	if _, err := r.add([]byte{0xff, 0xff, 0xff}); err == nil {
		t.Error("want an error for a malformed part")
	}

	mustPart := func(m *pb.MultiPartMessage) []byte {
		b, err := proto.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	if _, err := r.add(mustPart(&pb.MultiPartMessage{MessageId: 1, MessageSize: 0})); err == nil {
		t.Error("want an error for a zero total size")
	}
	if _, err := r.add(mustPart(&pb.MultiPartMessage{MessageId: 1, MessageSize: 10, DataIndex: -1})); err == nil {
		t.Error("want an error for a negative position")
	}
	if _, err := r.add(mustPart(&pb.MultiPartMessage{MessageId: 1, MessageSize: 10, DataIndex: 99})); err == nil {
		t.Error("want an error for a position past the end")
	}

	// A frame that claims an enormous message must not be allowed to exhaust
	// memory here.
	limited := newReassembler(1 << 20)
	if _, err := limited.add(mustPart(&pb.MultiPartMessage{MessageId: 2, MessageSize: 1 << 30})); err == nil {
		t.Error("want an error for a message over the limit")
	}
}

func TestReassembleRejectsChangedSize(t *testing.T) {
	r := newReassembler(0)
	first, _ := proto.Marshal(&pb.MultiPartMessage{MessageId: 9, MessageSize: 40000, DataIndex: 0, MessageData: make([]byte, 10)})
	if _, err := r.add(first); err != nil {
		t.Fatal(err)
	}
	second, _ := proto.Marshal(&pb.MultiPartMessage{MessageId: 9, MessageSize: 50000, DataIndex: 1, MessageData: make([]byte, 10)})
	if _, err := r.add(second); err == nil {
		t.Error("want an error when a message changes size mid-flight")
	}
}

// A peer that starts transfers and abandons them must not be able to grow this
// without limit.
func TestReassembleBoundsPartialMessages(t *testing.T) {
	r := newReassembler(0)
	start := func(id int64) error {
		b, err := proto.Marshal(&pb.MultiPartMessage{
			MessageId: id, MessageSize: 10 * chunkSize, DataIndex: 0, MessageData: make([]byte, 10),
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = r.add(b)
		return err
	}
	for i := range maxPartialMessages {
		if err := start(int64(i)); err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
	}
	if err := start(9999); err == nil {
		t.Error("want an error once the limit is reached")
	}
	r.reset()
	if r.pending() != 0 {
		t.Error("reset did not discard the part-received messages")
	}
	if err := start(9999); err != nil {
		t.Errorf("after reset: %v", err)
	}
}

// The position is chosen by the sender, so the offset it implies must not be
// allowed to wrap into a value that passes the bounds check.
func TestReassembleRejectsOverflowingPosition(t *testing.T) {
	r := newReassembler(0)
	b, err := proto.Marshal(&pb.MultiPartMessage{
		MessageId: 1, MessageSize: 40000, DataIndex: 1 << 30, MessageData: make([]byte, 10),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.add(b); err == nil {
		t.Error("want an error for a position far past the end")
	}
}
