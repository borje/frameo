package sdg

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

func TestTellPacketGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFrame(&buf, tellPacket()); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	// Frame length 10: a two-byte length of 8, the magic, and "TELL".
	want := "0008f09f909f54454c4c"
	if got := hex.EncodeToString(buf.Bytes()); got != want {
		t.Errorf("TELL frame = %s, want %s", got, want)
	}
}

func TestPacketCommand(t *testing.T) {
	body := buildPacket(cmdWelc, 3)
	copy(body[headerSize:], []byte{1, 2, 3})

	cmd, payload, err := packetCommand(body)
	if err != nil {
		t.Fatalf("packetCommand: %v", err)
	}
	if cmd != cmdWelc {
		t.Errorf("command = %q, want %q", cmd, cmdWelc)
	}
	if !bytes.Equal(payload, []byte{1, 2, 3}) {
		t.Errorf("payload = %v, want [1 2 3]", payload)
	}
}

func TestPacketCommandRejectsBadMagic(t *testing.T) {
	body := buildPacket(cmdWelc, 0)
	body[0] ^= 0xff
	if _, _, err := packetCommand(body); !errors.Is(err, ErrProtocol) {
		t.Errorf("err = %v, want ErrProtocol", err)
	}
	if _, _, err := packetCommand([]byte{1, 2, 3}); !errors.Is(err, ErrProtocol) {
		t.Errorf("short packet err = %v, want ErrProtocol", err)
	}
}

func TestReadFrame(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		var buf bytes.Buffer
		payload := bytes.Repeat([]byte{0xab}, 4000)
		if err := writeFrame(&buf, payload); err != nil {
			t.Fatalf("writeFrame: %v", err)
		}
		got, err := readFrame(&buf, 16416)
		if err != nil {
			t.Fatalf("readFrame: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Error("round trip changed the body")
		}
	})

	t.Run("empty frame rejected", func(t *testing.T) {
		if _, err := readFrame(bytes.NewReader([]byte{0, 0}), 100); !errors.Is(err, ErrProtocol) {
			t.Errorf("err = %v, want ErrProtocol", err)
		}
	})

	t.Run("over limit rejected before allocating", func(t *testing.T) {
		if _, err := readFrame(bytes.NewReader([]byte{0xff, 0xff}), 100); !errors.Is(err, ErrProtocol) {
			t.Errorf("err = %v, want ErrProtocol", err)
		}
	})

	t.Run("clean EOF is io.EOF", func(t *testing.T) {
		if _, err := readFrame(bytes.NewReader(nil), 100); !errors.Is(err, io.EOF) {
			t.Errorf("err = %v, want io.EOF", err)
		}
	})

	t.Run("truncated body", func(t *testing.T) {
		_, err := readFrame(bytes.NewReader([]byte{0, 10, 1, 2}), 100)
		if !errors.Is(err, ErrProtocol) {
			t.Errorf("err = %v, want ErrProtocol", err)
		}
	})
}

func TestWriteFrameRejectsOversize(t *testing.T) {
	err := writeFrame(io.Discard, make([]byte, maxFrame+1))
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Errorf("err = %v, want ErrMessageTooLarge", err)
	}
}
