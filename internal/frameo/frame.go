// SPDX-License-Identifier: GPL-3.0-or-later

package frameo

import (
	"encoding/binary"
	"fmt"

	"google.golang.org/protobuf/proto"
)

// Frame is one decoded message.
type Frame struct {
	Type    int32
	Payload []byte
}

func (f Frame) String() string {
	return fmt.Sprintf("%s(%d), %d bytes", typeName(f.Type), f.Type, len(f.Payload))
}

// encodeFrame wraps a protobuf in the two-word header the frame expects.
func encodeFrame(msgType int32, m proto.Message) ([]byte, error) {
	pb, err := proto.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("frameo: encode %s: %w", typeName(msgType), err)
	}
	return encodeFrameBytes(msgType, pb), nil
}

// encodeFrameBytes wraps an already-encoded payload.
func encodeFrameBytes(msgType int32, payload []byte) []byte {
	buf := make([]byte, frameHeader+len(payload))
	binary.BigEndian.PutUint32(buf[0:4], framePrefix)
	binary.BigEndian.PutUint32(buf[4:8], uint32(msgType))
	copy(buf[frameHeader:], payload)
	return buf
}

// decodeFrame splits a message into its type and payload.
func decodeFrame(b []byte) (Frame, error) {
	if len(b) < frameHeader {
		return Frame{}, fmt.Errorf("frameo: message of %d bytes is shorter than a header", len(b))
	}
	if prefix := binary.BigEndian.Uint32(b[0:4]); prefix != framePrefix {
		return Frame{}, fmt.Errorf("frameo: message prefix is %d, want %d", prefix, framePrefix)
	}
	return Frame{
		Type:    int32(binary.BigEndian.Uint32(b[4:8])),
		Payload: b[frameHeader:],
	}, nil
}
