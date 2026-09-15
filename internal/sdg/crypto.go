// SPDX-License-Identifier: GPL-3.0-or-later

package sdg

import (
	"fmt"

	"golang.org/x/crypto/nacl/box"
)

// boxOverhead is the number of bytes a crypto_box adds to its plaintext.
const boxOverhead = box.Overhead // 16

// This package speaks to an implementation built on libsodium's original NaCl
// API, where crypto_box takes a plaintext with 32 leading zero bytes and
// produces a ciphertext with 16 leading zero bytes. Go's nacl/box uses the
// "easy" convention instead: no padding on input, and the output is the
// 16-byte authenticator followed by the ciphertext. The two produce identical
// bytes once the leading zeros are dropped, so nothing here ever pads. A
// plaintext of n bytes always seals to exactly n+16 bytes on the wire.

// seal encrypts to a recipient's public key with our private key.
func seal(plain []byte, nonce [nonceSize]byte, peerPub, ourPriv *Key) []byte {
	return box.Seal(nil, plain, &nonce, (*[32]byte)(peerPub), (*[32]byte)(ourPriv))
}

// open decrypts a box addressed to us from a known sender.
func open(ciphertext []byte, nonce [nonceSize]byte, peerPub, ourPriv *Key) ([]byte, error) {
	plain, ok := box.Open(nil, ciphertext, &nonce, (*[32]byte)(peerPub), (*[32]byte)(ourPriv))
	if !ok {
		return nil, ErrDecrypt
	}
	return plain, nil
}

// precompute derives the shared session key from an ephemeral key pair. This is
// byte-for-byte libsodium's crypto_box_beforenm, which matters beyond
// performance: the pairing exchange reuses the result as a Curve25519 scalar.
func precompute(peerPub, ourPriv *Key) [32]byte {
	var shared [32]byte
	box.Precompute(&shared, (*[32]byte)(peerPub), (*[32]byte)(ourPriv))
	return shared
}

// sealShared encrypts with an already-derived session key.
func sealShared(plain []byte, nonce [nonceSize]byte, shared *[32]byte) []byte {
	return box.SealAfterPrecomputation(nil, plain, &nonce, shared)
}

// openShared decrypts with an already-derived session key.
func openShared(ciphertext []byte, nonce [nonceSize]byte, shared *[32]byte) ([]byte, error) {
	plain, ok := box.OpenAfterPrecomputation(nil, ciphertext, &nonce, shared)
	if !ok {
		return nil, ErrDecrypt
	}
	return plain, nil
}

// errShort reports a packet that is too small for the fields it must contain.
func errShort(what string, got, want int) error {
	return fmt.Errorf("%w: %s is %d bytes, want at least %d", ErrProtocol, what, got, want)
}
