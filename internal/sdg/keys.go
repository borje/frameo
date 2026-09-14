package sdg

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// KeySize is the length of every key and peer id in the protocol.
const KeySize = 32

// Key is a 32-byte Curve25519 key.
type Key [KeySize]byte

// PeerID identifies a device on the grid. It is literally that device's
// long-term public key: the value a frame presents in its WELC packet and the
// value pairing yields.
type PeerID = Key

// String renders the key as lowercase hex, the form the grid's control
// protocol uses for peer ids.
func (k Key) String() string { return hex.EncodeToString(k[:]) }

// ParseKey decodes a 64-character hex string into a Key.
func ParseKey(s string) (Key, error) {
	var k Key
	b, err := hex.DecodeString(s)
	if err != nil {
		return k, fmt.Errorf("sdg: parse key: %w", err)
	}
	if len(b) != KeySize {
		return k, fmt.Errorf("sdg: parse key: got %d bytes, want %d", len(b), KeySize)
	}
	copy(k[:], b)
	return k, nil
}

// Identity is this client's long-term key pair. Its public half is the peer id
// other devices know us by, so it must be persisted across runs: a frame is
// paired to this key, not to the machine.
type Identity struct {
	Private Key
	Public  Key
}

// NewIdentity generates a fresh long-term key pair.
func NewIdentity() (*Identity, error) {
	var priv Key
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, fmt.Errorf("sdg: generate identity: %w", err)
	}
	return IdentityFromPrivate(priv), nil
}

// IdentityFromPrivate derives the public half of an existing private key.
func IdentityFromPrivate(priv Key) *Identity {
	id := &Identity{Private: priv}
	pub, _ := curve25519.X25519(priv[:], curve25519.Basepoint)
	copy(id.Public[:], pub)
	return id
}

// generateEphemeral creates a short-term key pair for one tunnel handshake.
func generateEphemeral() (pub, priv Key, err error) {
	if _, err := rand.Read(priv[:]); err != nil {
		return pub, priv, fmt.Errorf("sdg: generate ephemeral key: %w", err)
	}
	p, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return pub, priv, fmt.Errorf("sdg: generate ephemeral key: %w", err)
	}
	copy(pub[:], p)
	return pub, priv, nil
}
