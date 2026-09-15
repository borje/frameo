// SPDX-License-Identifier: GPL-3.0-or-later

package sdgtest

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/salsa20"
)

// EchoDevice returns a handler that sends every message it receives straight
// back.
func EchoDevice() PeerHandler {
	return func(t *Tunnel) {
		for {
			msg, err := t.Recv()
			if err != nil {
				return
			}
			if err := t.Send(msg); err != nil {
				return
			}
		}
	}
}

// PairingDevice returns a handler that runs the device side of the pairing
// exchange for the given full code. If it is given a different code than the
// client uses, the exchange fails the way a mistyped code does.
//
// The device chooses a scalar x and presents X = x*P, where P is the point
// both sides derive from the code. The client answers with X' = r*P, so each
// side can reach the same secret without either revealing its scalar: the
// device computes x*X' and the client computes r*X.
func PairingDevice(fullOTP string, report func(error)) PeerHandler {
	return func(t *Tunnel) {
		if err := runDevicePairing(t, fullOTP); err != nil && report != nil {
			report(err)
		}
	}
}

// WrongResultDevice pairs correctly but reports a result the client cannot
// have derived, standing in for a device that is not who it claims to be.
func WrongResultDevice(fullOTP string) PeerHandler {
	return func(t *Tunnel) {
		_ = runDevicePairingWith(t, fullOTP, func(result []byte) []byte {
			bad := append([]byte{}, result...)
			bad[0] ^= 0xff
			return bad
		})
	}
}

func runDevicePairing(t *Tunnel, fullOTP string) error {
	return runDevicePairingWith(t, fullOTP, nil)
}

func runDevicePairingWith(t *Tunnel, fullOTP string, tamper func([]byte) []byte) error {
	h0 := sha512.Sum512(append(append([]byte(fullOTP), t.clientLongPK[:]...), t.long.Public[:]...))

	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	h1 := sha512.Sum512(append(h0[:], nonce[:]...))

	var secretScalar [32]byte
	if _, err := rand.Read(secretScalar[:]); err != nil {
		return err
	}
	var y [32]byte
	salsa20.XORKeyStream(y[:], secretScalar[:], nonce[:24], (*[32]byte)(h1[:32]))

	base, err := curve25519.X25519(t.shared[:], curve25519.Basepoint)
	if err != nil {
		return err
	}
	p1, err := curve25519.X25519(secretScalar[:], base)
	if err != nil {
		return err
	}

	var x [32]byte
	if _, err := rand.Read(x[:]); err != nil {
		return err
	}
	bigX, err := curve25519.X25519(x[:], p1)
	if err != nil {
		return err
	}

	challenge := make([]byte, 0, 97)
	challenge = append(challenge, 3)
	challenge = append(challenge, bigX...)
	challenge = append(challenge, nonce[:]...)
	challenge = append(challenge, y[:]...)
	if err := t.Send(challenge); err != nil {
		return err
	}

	resp, err := t.Recv()
	if err != nil {
		return err
	}
	if len(resp) < 65 || resp[0] != 4 {
		return fmt.Errorf("sdgtest: expected a pairing response, got % x", resp)
	}
	respX, respY := resp[1:33], resp[33:65]

	secret, err := curve25519.X25519(x[:], respX)
	if err != nil {
		return err
	}
	hashWith := func(point []byte) []byte {
		inner := sha512.Sum512(point)
		outer := sha512.Sum512(append(inner[:], secret...))
		return outer[:32]
	}
	if !bytes.Equal(hashWith(bigX), respY) {
		return errors.New("sdgtest: client's pairing response did not verify")
	}

	result := hashWith(respX)
	if tamper != nil {
		result = tamper(result)
	}
	return t.Send(append([]byte{5}, result...))
}
