// SPDX-License-Identifier: GPL-3.0-or-later

package sdg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Every frame on an SDG connection is a 16-bit big-endian length followed by
// that many bytes. Before the encrypted tunnel starts, the body of a frame is a
// relay control message: a single type byte and a protobuf. Once the tunnel
// handshake begins, the body is an SDG packet:
//
//	offset  size  field
//	0       4     magic  f0 9f 90 9f
//	4       4     command, four ASCII characters
//	8       ...   command-specific payload
//
// Offsets in this file are relative to the body, so they are two less than the
// offsets counted from the start of the frame.
const (
	lengthPrefix = 2
	magicSize    = 4
	commandSize  = 4
	headerSize   = magicSize + commandSize // 8, body-relative

	// maxFrame is the largest body the 16-bit length can describe.
	maxFrame = 0xffff
)

// magicBytes marks the start of a tunnel packet.
var magicBytes = [magicSize]byte{0xf0, 0x9f, 0x90, 0x9f}

// Tunnel commands. The protocol follows CurveCP's handshake shape with its own
// packet layout.
const (
	cmdTell = "TELL" // client: tell me your public key
	cmdWelc = "WELC" // server: here it is
	cmdHelo = "HELO" // client: ephemeral key, encrypted to your long-term key
	cmdCook = "COOK" // server: my ephemeral key plus a cookie, in a crypto box
	cmdVoch = "VOCH" // client: my long-term key, vouching for my ephemeral key
	cmdRedy = "REDY" // server: tunnel established
	cmdMesg = "MESG" // both: an encrypted message
)

// Relay control message types, exchanged unencrypted before the tunnel exists
// and encrypted inside MESG afterwards. Note that 1 means two different things
// depending on which side of the tunnel handshake we are on.
const (
	msgForwardRemote    = 0
	msgProtocolVersion  = 1
	msgForwardHold      = 1
	msgForwardReply     = 2
	msgForwardError     = 3
	msgPing             = 4
	msgPong             = 5
	msgCallRemote       = 10
	msgRemoteReply      = 11
	msgIncomingCall     = 12
	msgIncomingCallResp = 13
	msgPairRemote       = 32
	msgPairRemoteReply  = 33
)

// Magic constants carried inside the relay control protobufs.
const (
	forwardRemoteMagic   = 0xF09D8C95
	protocolVersionMagic = 0xF09D8CA8
	protocolVersionMajor = 1
	protocolVersionMinor = 0
	forwardSignature     = "Mdg-NaCl/binary"
)

// readFrame reads one length-prefixed frame and returns its body. limit caps
// the body size; a larger frame is a protocol error rather than an allocation.
func readFrame(r io.Reader, limit int) ([]byte, error) {
	var hdr [lengthPrefix]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			err = io.EOF
		}
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 {
		return nil, fmt.Errorf("%w: empty frame", ErrProtocol)
	}
	if limit > 0 && n > limit {
		return nil, fmt.Errorf("%w: frame of %d bytes exceeds the %d byte limit",
			ErrProtocol, n, limit)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("%w: short frame body: %w", ErrProtocol, err)
	}
	return body, nil
}

// writeFrame writes one length-prefixed frame.
func writeFrame(w io.Writer, body []byte) error {
	if len(body) > maxFrame {
		return fmt.Errorf("%w: %d bytes does not fit a 16-bit length", ErrMessageTooLarge, len(body))
	}
	buf := make([]byte, lengthPrefix+len(body))
	binary.BigEndian.PutUint16(buf, uint16(len(body)))
	copy(buf[lengthPrefix:], body)
	_, err := w.Write(buf)
	return err
}

// buildPacket assembles a tunnel packet body: magic, command, payload.
func buildPacket(cmd string, payloadLen int) []byte {
	body := make([]byte, headerSize+payloadLen)
	copy(body[0:magicSize], magicBytes[:])
	copy(body[magicSize:headerSize], cmd)
	return body
}

// packetCommand validates the magic and returns the command of a tunnel packet
// body along with the payload that follows it.
func packetCommand(body []byte) (string, []byte, error) {
	if len(body) < headerSize {
		return "", nil, fmt.Errorf("%w: packet of %d bytes is shorter than a header", ErrProtocol, len(body))
	}
	if [magicSize]byte(body[0:magicSize]) != magicBytes {
		return "", nil, fmt.Errorf("%w: bad packet magic %x", ErrProtocol, body[0:magicSize])
	}
	return string(body[magicSize:headerSize]), body[headerSize:], nil
}

// tellPacket is a constant: TELL carries no payload.
func tellPacket() []byte { return buildPacket(cmdTell, 0) }
