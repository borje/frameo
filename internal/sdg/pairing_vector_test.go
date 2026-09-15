// SPDX-License-Identifier: GPL-3.0-or-later

package sdg

import (
	"encoding/hex"
	"testing"
)

// TestPairingResponseMatchesReference checks the pairing computation against
// values produced by the reference implementation's own code path, compiled
// against libsodium with the random scalar fixed. It is the one test that can
// tell a self-consistent reimplementation apart from a correct one: everything
// else in this package would agree with itself even if the derivation were
// subtly wrong, and a real frame would simply refuse to pair.
//
// The generator is scratchpad/pairvec.c in the session that produced this port;
// it is a verbatim copy of the challenge handler from opensdg peer.c.
func TestPairingResponseMatchesReference(t *testing.T) {
	const otp = "12345678"

	var clientPK, serverPK Key
	var shared [32]byte
	var ch pairingChallenge
	var rnd [KeySize]byte
	for i := range 32 {
		clientPK[i] = byte(i + 1)
		serverPK[i] = byte(0xa0 + i)
		shared[i] = byte(0x10 + i)
		ch.Nonce[i] = byte(0x40 + i)
		ch.Y[i] = byte(0x70 + i)
		rnd[i] = byte(0xc0 + i)
	}
	mustHex(t, ch.X[:], "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254")

	resp, expected, err := pairingResponse(otp, &clientPK, &serverPK, &shared, ch, rnd)
	if err != nil {
		t.Fatalf("pairingResponse: %v", err)
	}
	if len(resp) != responseSize {
		t.Fatalf("response is %d bytes, want %d", len(resp), responseSize)
	}
	if resp[0] != msgPairingResponse {
		t.Errorf("response type = %d, want %d", resp[0], msgPairingResponse)
	}

	checks := []struct {
		name string
		got  []byte
		want string
	}{
		{"X", resp[1:33], "eff3f1b06110e23bc2858f1db21b409aa90866a9260cbc4fd186a4ce62cf1e5b"},
		{"Y", resp[33:65], "6ebdb5069bb8cc08c63a7a3b75443684834276b803b131045d47637327432965"},
		{"expected result", expected[:], "c9886c250d44939dec0b21aacc133ab1b78695397b0c5f383fa7e4c055ab23f7"},
	}
	for _, c := range checks {
		if got := hex.EncodeToString(c.got); got != c.want {
			t.Errorf("%s = %s, want %s", c.name, got, c.want)
		}
	}
}

// mustHex fills dst from a hex string.
func mustHex(t *testing.T, dst []byte, s string) {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	copy(dst, b)
}

func TestParseChallengeRejectsShort(t *testing.T) {
	if _, err := parseChallenge(make([]byte, challengeSize-1)); err == nil {
		t.Error("want an error for a truncated challenge")
	}
}
