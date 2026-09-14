package sdg

import (
	"bytes"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// The packets below were produced by compiling the reference implementation's
// own packet-building code against libsodium with every random input fixed,
// and dumping the result. Matching them byte for byte is what says this port
// speaks the protocol rather than merely speaking to itself: the fake server in
// sdgtest would happily agree with a client that had, say, the nonce counter
// endianness backwards.
//
// The generator is scratchpad/layout.c in the session that produced this port;
// it includes opensdg's tunnel_protocol.h directly, so the struct layouts come
// from the reference source rather than from a transcription of it.
//
// Inputs: server secret key 0xa0..0xbf, client secret key 0x01..0x20, client
// ephemeral secret 0x50..0x6f, server ephemeral secret 0x80..0x9f, cookie
// 0x00..0x5f, VOCH inner nonce tail 0xe0..0xef.
const (
	refHELO = "0080f09f909f48454c4f392d174a38b3b1beafaf1fe824870841c5fa531bc6eafdb6402c124664488c1c0000" +
		"0000000000003b8c384e099796e1c716e8debb6a7dffd80a999048d5973f6aa2cb900b581950ae08306f0cea1f0a" +
		"22ffebdcec3ee6c27676f5d579c942ea2207ca945ac5c5e71e533cfae28d05629da0820dd34640b8"
	refVOCH = "016ff09f909f564f4348000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021" +
		"22232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f" +
		"505152535455565758595a5b5c5d5e5f0000000000000001ba5c7b1d43165fb3a68ffb67530169769883fe77b863" +
		"69fe3d149316889ba5cc8b9886aa43a4ecafb6ca4e209ad794e4dbcdbab8b837ab54a4e00287a544909774fad668" +
		"e70d881afa58a317c12f94d67dcec45c9aa6dd65d84d8f8a1139de5c1141c48cb62c1e89d3178c997c197042581a" +
		"5878ac340ab1f8c3b267388098aed1abdbde30f5d1e57997786158861d8ccee097209944bc80078a2e4d1507e646" +
		"0c865143cec56283d5da25eca84bfdfb2ed448115af3e7415cee02423e6224c7d17cb8d1bdd04810e775e3b31485" +
		"acd40aaf075bf5d2ad0737e173e2f83b18bc071eeab64018eabbc85541ef7aa8030a06c186956510e0370a2a4687" +
		"9a5ecf"
	refMESG      = "0028f09f909f4d45534700000000000000022aae70bb95881fa9c2a612d7f5d401fc291d6e7f2fabe4a3"
	refBeforenm  = "e6c55502fce47eaddcf296ef4219ed87eba5692dc84bedf702ea8915ba744d30"
	refClientPub = "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c"
	refServerPub = "605a725d2a4adfeeb1a29e17edd621c1b7593ee8cdbc44ac6c4ab6e2f805d23c"
	refShortPub  = "392d174a38b3b1beafaf1fe824870841c5fa531bc6eafdb6402c124664488c1c"
)

// refFixture rebuilds the key material the reference dump was made with.
type refFixture struct {
	client, server, short, serverShort *Identity
	shared                             [32]byte
	cookie                             []byte
	r                                  [16]byte
}

func newRefFixture(t *testing.T) refFixture {
	t.Helper()
	fill := func(start byte) Key {
		var k Key
		for i := range k {
			k[i] = start + byte(i)
		}
		return k
	}
	f := refFixture{
		client:      IdentityFromPrivate(fill(0x01)),
		server:      IdentityFromPrivate(fill(0xa0)),
		short:       IdentityFromPrivate(fill(0x50)),
		serverShort: IdentityFromPrivate(fill(0x80)),
	}
	f.shared = precompute(&f.serverShort.Public, &f.short.Private)
	f.cookie = make([]byte, cookieSize)
	for i := range f.cookie {
		f.cookie[i] = byte(i)
	}
	for i := range f.r {
		f.r[i] = 0xe0 + byte(i)
	}
	return f
}

// frameHex renders a packet body the way it appears on the wire, length
// prefix included, so it can be compared with the reference dump.
func frameHex(body []byte) string {
	var buf bytes.Buffer
	_ = writeFrame(&buf, body)
	return hex.EncodeToString(buf.Bytes())
}

func TestKeyDerivationMatchesReference(t *testing.T) {
	f := newRefFixture(t)

	// X25519 against the base point must agree with crypto_scalarmult_base.
	for _, c := range []struct {
		name string
		got  Key
		want string
	}{
		{"client public key", f.client.Public, refClientPub},
		{"server public key", f.server.Public, refServerPub},
		{"ephemeral public key", f.short.Public, refShortPub},
	} {
		if got := hex.EncodeToString(c.got[:]); got != c.want {
			t.Errorf("%s = %s, want %s", c.name, got, c.want)
		}
	}

	// The session key must agree with crypto_box_beforenm, not merely produce
	// interoperable encryption: the pairing exchange reuses these bytes as a
	// scalar, where any difference would show up only against a real device.
	if got := hex.EncodeToString(f.shared[:]); got != refBeforenm {
		t.Errorf("session key = %s, want %s", got, refBeforenm)
	}
	if _, err := curve25519.X25519(f.shared[:], curve25519.Basepoint); err != nil {
		t.Errorf("session key is not usable as a scalar: %v", err)
	}
}

func TestHeloMatchesReference(t *testing.T) {
	f := newRefFixture(t)
	body := encodeHelo(f.short.Public, 0, &f.server.Public, &f.short.Private)
	if got := frameHex(body); got != refHELO {
		t.Errorf("HELO frame does not match the reference implementation\n got %s\nwant %s", got, refHELO)
	}
}

func TestVochMatchesReference(t *testing.T) {
	f := newRefFixture(t)
	body := encodeVochWith(f.cookie, 1, f.r, &f.client.Public, &f.client.Private,
		&f.short.Public, &f.server.Public, &f.shared, certificateBlob(nil))
	if got := frameHex(body); got != refVOCH {
		t.Errorf("VOCH frame does not match the reference implementation\n got %s\nwant %s", got, refVOCH)
	}
}

func TestMesgMatchesReference(t *testing.T) {
	f := newRefFixture(t)
	body := encodeMesg([]byte("frameo"), 2, &f.shared)
	if got := frameHex(body); got != refMESG {
		t.Errorf("MESG frame does not match the reference implementation\n got %s\nwant %s", got, refMESG)
	}
}
