package sdg

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/salsa20"
)

// Pairing message types, sent as raw fixed-size structures rather than
// protobufs.
const (
	msgPairingChallenge = 3
	msgPairingResponse  = 4
	msgPairingResult    = 5
)

const (
	challengeSize = 1 + KeySize + 32 + 32 // 97
	responseSize  = 1 + KeySize + 32      // 65
	resultSize    = 1 + 32                // 33
)

// pairingChallenge is what the device sends once the tunnel is up.
type pairingChallenge struct {
	X     [KeySize]byte
	Nonce [32]byte
	Y     [32]byte
}

func parseChallenge(data []byte) (pairingChallenge, error) {
	var ch pairingChallenge
	if len(data) < challengeSize {
		return ch, errShort("pairing challenge", len(data), challengeSize)
	}
	copy(ch.X[:], data[1:33])
	copy(ch.Nonce[:], data[33:65])
	copy(ch.Y[:], data[65:97])
	return ch, nil
}

// pairingResponse answers a pairing challenge.
//
// The device and this client each know the full code but have never exchanged
// it. The code, both long-term keys and the device's nonce derive a keystream
// that unmasks the device's Y into a Curve25519 point. Only a party that knows
// the code recovers the same point, so only that party can produce an X that
// the device will accept, and both sides arrive at the same shared secret to
// hash into the result.
//
// It is written as a pure function, with the random scalar supplied by the
// caller, so the exchange can be tested against known values.
func pairingResponse(otp string, clientPK, serverPK *Key, shared *[32]byte, ch pairingChallenge, rnd [KeySize]byte) (resp []byte, expected [32]byte, err error) {
	h0 := sha512.Sum512(append(append([]byte(otp), clientPK[:]...), serverPK[:]...))
	h1 := sha512.Sum512(append(h0[:], ch.Nonce[:]...))

	var mask [32]byte
	var nonce [nonceSize]byte
	copy(nonce[:], ch.Nonce[:nonceSize])
	salsa20.XORKeyStream(mask[:], ch.Y[:], nonce[:], (*[32]byte)(h1[:32]))

	base, err := curve25519.X25519(shared[:], curve25519.Basepoint)
	if err != nil {
		return nil, expected, fmt.Errorf("sdg: pairing: %w: %w", ErrProtocol, err)
	}
	p1, err := curve25519.X25519(mask[:], base)
	if err != nil {
		return nil, expected, fmt.Errorf("sdg: pairing: %w: %w", ErrProtocol, err)
	}
	respX, err := curve25519.X25519(rnd[:], p1)
	if err != nil {
		return nil, expected, fmt.Errorf("sdg: pairing: %w: %w", ErrProtocol, err)
	}
	secret, err := curve25519.X25519(rnd[:], ch.X[:])
	if err != nil {
		return nil, expected, fmt.Errorf("sdg: pairing: %w: %w", ErrProtocol, err)
	}

	hashWith := func(point []byte) [32]byte {
		inner := sha512.Sum512(point)
		outer := sha512.Sum512(append(inner[:], secret...))
		return [32]byte(outer[:32])
	}
	respY := hashWith(ch.X[:])
	expected = hashWith(respX)

	resp = make([]byte, 0, responseSize)
	resp = append(resp, msgPairingResponse)
	resp = append(resp, respX...)
	resp = append(resp, respY[:]...)
	return resp, expected, nil
}

// runPairing performs the challenge exchange on an established pairing tunnel.
func runPairing(c *conn, otpDigits string, clientPK *Key) error {
	data, err := c.recvMESG()
	if err != nil {
		return fmt.Errorf("sdg: pairing: awaiting challenge: %w", err)
	}
	if len(data) == 0 || data[0] != msgPairingChallenge {
		return fmt.Errorf("sdg: pairing: %w: expected a challenge, got message type %v",
			ErrProtocol, firstByte(data))
	}
	ch, err := parseChallenge(data)
	if err != nil {
		return fmt.Errorf("sdg: pairing: %w", err)
	}

	var rnd [KeySize]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return fmt.Errorf("sdg: pairing: %w", err)
	}
	resp, expected, err := pairingResponse(otpDigits, clientPK, &c.serverLongPK, &c.shared, ch, rnd)
	if err != nil {
		return err
	}
	if err := c.sendMESG(resp); err != nil {
		return fmt.Errorf("sdg: pairing: send response: %w", err)
	}

	data, err = c.recvMESG()
	if err != nil {
		return fmt.Errorf("sdg: pairing: awaiting result: %w", err)
	}
	if len(data) < resultSize || data[0] != msgPairingResult {
		return fmt.Errorf("sdg: pairing: %w: expected a result, got message type %v",
			ErrProtocol, firstByte(data))
	}
	if subtle.ConstantTimeCompare(data[1:resultSize], expected[:]) != 1 {
		return ErrPairingFailed
	}
	return nil
}

func firstByte(b []byte) any {
	if len(b) == 0 {
		return "nothing"
	}
	return b[0]
}
