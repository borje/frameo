// SPDX-License-Identifier: GPL-3.0-or-later

package sdgtest

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// Key is a 32-byte Curve25519 key.
type Key [32]byte

// KeyPair is a long-term or ephemeral key pair.
type KeyPair struct {
	Public  Key
	Private Key
}

// NewKeyPair generates a key pair.
func NewKeyPair() (KeyPair, error) {
	pub, priv, err := box.GenerateKey(cryptoRand{})
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{Public: Key(*pub), Private: Key(*priv)}, nil
}

// KeyPairFromPrivate derives the public half of a private key.
func KeyPairFromPrivate(priv Key) KeyPair {
	pub, _ := curve25519.X25519(priv[:], curve25519.Basepoint)
	return KeyPair{Public: Key(pub), Private: priv}
}

var magic = [4]byte{0xf0, 0x9f, 0x90, 0x9f}

// Tunnel is the server end of one encrypted connection.
type Tunnel struct {
	nc net.Conn
	br *bufio.Reader

	long  KeyPair
	short KeyPair

	clientLongPK Key
	shared       [32]byte
	cookie       [96]byte

	ctr uint64

	// Properties are the entries of the client's VOCH trailer, by name. A
	// grid connection sends a licence certificate, a direct local connection
	// sends the service it is calling, and a relayed peer connection sends
	// nothing at all.
	Properties map[string][]byte

	// lastClientCtr tracks the client's nonce counter so tests can assert it
	// advances by one per encrypted packet, which a real server relies on.
	lastClientCtr uint64
	seenCtr       bool
}

func newTunnel(nc net.Conn, long KeyPair) *Tunnel {
	return &Tunnel{nc: nc, br: bufio.NewReader(nc), long: long}
}

func (t *Tunnel) readFrame() ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(t.br, hdr[:]); err != nil {
		return nil, err
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(t.br, body); err != nil {
		return nil, err
	}
	return body, nil
}

func (t *Tunnel) writeFrame(body []byte) error {
	buf := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(buf, uint16(len(body)))
	copy(buf[2:], body)
	_, err := t.nc.Write(buf)
	return err
}

func (t *Tunnel) readPacket() (string, []byte, error) {
	body, err := t.readFrame()
	if err != nil {
		return "", nil, err
	}
	if len(body) < 8 || [4]byte(body[0:4]) != magic {
		return "", nil, fmt.Errorf("sdgtest: bad packet: % x", body)
	}
	return string(body[4:8]), body[8:], nil
}

func (t *Tunnel) writePacket(cmd string, payload []byte) error {
	body := make([]byte, 8+len(payload))
	copy(body[0:4], magic[:])
	copy(body[4:8], cmd)
	copy(body[8:], payload)
	return t.writeFrame(body)
}

func shortNonce(prefix string, ctr uint64) [24]byte {
	var n [24]byte
	copy(n[:16], prefix)
	binary.BigEndian.PutUint64(n[16:], ctr)
	return n
}

func longNonce(prefix string, tail []byte) [24]byte {
	var n [24]byte
	copy(n[:8], prefix)
	copy(n[8:], tail)
	return n
}

// checkClientCtr verifies the client's nonce counter never repeats or goes
// backwards. A real server drops packets that violate this, silently, so it is
// worth failing loudly here instead.
func (t *Tunnel) checkClientCtr(ctr uint64) error {
	if t.seenCtr && ctr <= t.lastClientCtr {
		return fmt.Errorf("sdgtest: client nonce counter went from %d to %d", t.lastClientCtr, ctr)
	}
	t.lastClientCtr, t.seenCtr = ctr, true
	return nil
}

// handshake runs the server side of the Tunnel setup. grid selects whether a
// licence certificate is required in the client's VOCH.
// TrailerRule says what a server requires of the client's VOCH trailer.
type TrailerRule int

const (
	// NoTrailer is a relayed peer connection: the grid has already said which
	// service is wanted, so the VOCH says nothing.
	NoTrailer TrailerRule = iota
	// NeedCertificate is a grid connection.
	NeedCertificate
	// NeedProtocol is a direct connection over the local network, where the
	// service name has nowhere else to travel.
	NeedProtocol
)

// Certificate is the licence blob the client sent, if any.
func (t *Tunnel) Certificate() []byte { return t.Properties["certificate"] }

// Protocol is the service name the client asked for, empty if it sent none.
func (t *Tunnel) Protocol() string { return string(t.Properties["protocol"]) }

func (t *Tunnel) handshake(rule TrailerRule) error {
	cmd, _, err := t.readPacket()
	if err != nil {
		return err
	}
	if cmd != "TELL" {
		return fmt.Errorf("sdgtest: expected TELL, got %s", cmd)
	}
	if err := t.writePacket("WELC", t.long.Public[:]); err != nil {
		return err
	}

	cmd, payload, err := t.readPacket()
	if err != nil {
		return err
	}
	if cmd != "HELO" {
		return fmt.Errorf("sdgtest: expected HELO, got %s", cmd)
	}
	if len(payload) != 120 {
		return fmt.Errorf("sdgtest: HELO payload is %d bytes, want 120", len(payload))
	}
	var clientShortPK Key
	copy(clientShortPK[:], payload[0:32])
	ctr := binary.BigEndian.Uint64(payload[32:40])
	if err := t.checkClientCtr(ctr); err != nil {
		return err
	}
	nonce := shortNonce("CurveCP-client-H", ctr)
	plain, ok := box.Open(nil, payload[40:], &nonce, (*[32]byte)(&clientShortPK), (*[32]byte)(&t.long.Private))
	if !ok {
		return errors.New("sdgtest: could not open HELO")
	}
	for _, b := range plain {
		if b != 0 {
			return errors.New("sdgtest: HELO plaintext is not all zeroes")
		}
	}

	if t.short, err = NewKeyPair(); err != nil {
		return err
	}
	for i := range t.cookie {
		t.cookie[i] = byte(i)
	}
	var cookTail [16]byte
	copy(cookTail[:], "cookie-nonce-16!")
	cookPlain := append(append([]byte{}, t.short.Public[:]...), t.cookie[:]...)
	cookNonce := longNonce("CurveCPK", cookTail[:])
	sealed := box.Seal(nil, cookPlain, &cookNonce, (*[32]byte)(&clientShortPK), (*[32]byte)(&t.long.Private))
	if err := t.writePacket("COOK", append(cookTail[:], sealed...)); err != nil {
		return err
	}

	box.Precompute((*[32]byte)(&t.shared), (*[32]byte)(&clientShortPK), (*[32]byte)(&t.short.Private))

	cmd, payload, err = t.readPacket()
	if err != nil {
		return err
	}
	if cmd != "VOCH" {
		return fmt.Errorf("sdgtest: expected VOCH, got %s", cmd)
	}
	if len(payload) < 104 {
		return fmt.Errorf("sdgtest: VOCH payload is %d bytes", len(payload))
	}
	if string(payload[0:96]) != string(t.cookie[:]) {
		return errors.New("sdgtest: VOCH echoed the wrong cookie")
	}
	ctr = binary.BigEndian.Uint64(payload[96:104])
	if err := t.checkClientCtr(ctr); err != nil {
		return err
	}
	vouchNonce := shortNonce("CurveCP-client-I", ctr)
	outer, ok := box.OpenAfterPrecomputation(nil, payload[104:], &vouchNonce, (*[32]byte)(&t.shared))
	if !ok {
		return errors.New("sdgtest: could not open the outer VOCH box")
	}
	if len(outer) < 97 {
		return fmt.Errorf("sdgtest: VOCH outer box is %d bytes", len(outer))
	}
	copy(t.clientLongPK[:], outer[0:32])
	innerNonce := longNonce("CurveCPV", outer[32:48])
	vouched, ok := box.Open(nil, outer[48:96], &innerNonce, (*[32]byte)(&t.clientLongPK), (*[32]byte)(&t.long.Private))
	if !ok {
		return errors.New("sdgtest: could not open the inner VOCH box")
	}
	if string(vouched) != string(clientShortPK[:]) {
		return errors.New("sdgtest: VOCH does not vouch for the ephemeral key used in HELO")
	}
	if t.Properties, err = parseTrailer(outer[96:]); err != nil {
		return err
	}
	switch rule {
	case NeedCertificate:
		if _, ok := t.Properties["certificate"]; !ok {
			return errors.New("sdgtest: grid VOCH arrived without a certificate")
		}
	case NeedProtocol:
		if p := t.Protocol(); p == "" {
			return errors.New("sdgtest: local VOCH arrived without a service name")
		}
	case NoTrailer:
		if len(t.Properties) > 0 {
			return errors.New("sdgtest: relayed peer VOCH must carry no properties")
		}
	}

	return t.writeRaw("REDY", "CurveCP-server-R", []byte{0})
}

// writeRaw seals a payload and sends it under the given command.
func (t *Tunnel) writeRaw(cmd, prefix string, plain []byte) error {
	ctr := t.ctr
	t.ctr++
	nonce := shortNonce(prefix, ctr)
	sealed := box.SealAfterPrecomputation(nil, plain, &nonce, (*[32]byte)(&t.shared))
	payload := make([]byte, 8+len(sealed))
	binary.BigEndian.PutUint64(payload[0:8], ctr)
	copy(payload[8:], sealed)
	return t.writePacket(cmd, payload)
}

// Send transmits one application message to the client.
func (t *Tunnel) Send(data []byte) error {
	plain := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(plain, uint16(len(data)))
	copy(plain[2:], data)
	return t.writeRaw("MESG", "CurveCP-server-M", plain)
}

// Recv reads one application message from the client.
func (t *Tunnel) Recv() ([]byte, error) {
	cmd, payload, err := t.readPacket()
	if err != nil {
		return nil, err
	}
	if cmd != "MESG" {
		return nil, fmt.Errorf("sdgtest: expected MESG, got %s", cmd)
	}
	if len(payload) < 8 {
		return nil, errors.New("sdgtest: short MESG")
	}
	ctr := binary.BigEndian.Uint64(payload[0:8])
	if err := t.checkClientCtr(ctr); err != nil {
		return nil, err
	}
	nonce := shortNonce("CurveCP-client-M", ctr)
	plain, ok := box.OpenAfterPrecomputation(nil, payload[8:], &nonce, (*[32]byte)(&t.shared))
	if !ok {
		return nil, errors.New("sdgtest: could not open MESG")
	}
	if len(plain) < 2 {
		return nil, errors.New("sdgtest: short MESG plaintext")
	}
	n := int(binary.BigEndian.Uint16(plain[0:2]))
	if n > len(plain)-2 {
		return nil, errors.New("sdgtest: MESG length prefix overruns the plaintext")
	}
	return plain[2 : 2+n], nil
}

type cryptoRand struct{}

func (cryptoRand) Read(p []byte) (int, error) { return rand.Read(p) }

// parseTrailer reads the properties at the end of an opened VOCH box: a count,
// then that many entries of a length-prefixed NUL-terminated name and a
// length-prefixed value.
func parseTrailer(b []byte) (map[string][]byte, error) {
	props := map[string][]byte{}
	if len(b) == 0 {
		return nil, errors.New("sdgtest: VOCH outer box has no trailer at all")
	}
	count := int(b[0])
	b = b[1:]
	for range count {
		if len(b) < 1 {
			return nil, errors.New("sdgtest: VOCH trailer ends inside a property name")
		}
		n := int(b[0])
		if len(b) < 1+n+1+1 {
			return nil, errors.New("sdgtest: VOCH property name runs past the trailer")
		}
		name := string(b[1 : 1+n])
		if b[1+n] != 0 {
			return nil, errors.New("sdgtest: VOCH property name is not NUL terminated")
		}
		b = b[1+n+1:]
		v := int(b[0])
		if len(b) < 1+v {
			return nil, errors.New("sdgtest: VOCH property value runs past the trailer")
		}
		props[name] = append([]byte{}, b[1:1+v]...)
		b = b[1+v:]
	}
	if len(b) != 0 {
		return nil, fmt.Errorf("sdgtest: %d bytes left over after the VOCH trailer", len(b))
	}
	return props, nil
}
