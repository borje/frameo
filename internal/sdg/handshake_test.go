package sdg

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
)

// testKeys returns a deterministic client identity and server identity.
func testKeys(t *testing.T) (client, server *Identity) {
	t.Helper()
	var cp, sp Key
	for i := range cp {
		cp[i] = byte(i + 1)
		sp[i] = byte(0xa0 + i)
	}
	return IdentityFromPrivate(cp), IdentityFromPrivate(sp)
}

// The wire sizes below are the sizes of the equivalent packed C structs in the
// reference implementation. They are asserted because the padding conventions
// of the two crypto_box APIs differ, and getting that mapping wrong changes
// the length before it changes anything else.
func TestPacketSizes(t *testing.T) {
	client, server := testKeys(t)
	shortPK, shortSK, err := generateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	var shared [32]byte

	helo := encodeHelo(shortPK, 0, &server.Public, &shortSK)
	if got, want := len(helo)+lengthPrefix, 130; got != want {
		t.Errorf("HELO frame = %d bytes, want %d", got, want)
	}

	cookie := make([]byte, cookieSize)

	peerVoch, err := encodeVoch(cookie, 1, &client.Public, &client.Private, &shortPK, &server.Public, &shared, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(peerVoch)+lengthPrefix, 227; got != want {
		t.Errorf("peer VOCH frame = %d bytes, want %d", got, want)
	}

	gridVoch, err := encodeVoch(cookie, 1, &client.Public, &client.Private, &shortPK, &server.Public, &shared, certificateBlob(nil))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(gridVoch)+lengthPrefix, 369; got != want {
		t.Errorf("grid VOCH frame = %d bytes, want %d", got, want)
	}

	mesg := encodeMesg([]byte("hello"), 2, &shared)
	if got, want := len(mesg)+lengthPrefix, 36+5; got != want {
		t.Errorf("MESG frame = %d bytes, want %d", got, want)
	}
}

func TestCertificateBlobGolden(t *testing.T) {
	blob := certificateBlob(nil)
	if len(blob) != 142 {
		t.Fatalf("certificate blob = %d bytes, want 142", len(blob))
	}
	want := "0b" + hex.EncodeToString([]byte("certificate\x00")) + "80"
	if got := hex.EncodeToString(blob[:14]); got != want {
		t.Errorf("blob header = %s, want %s", got, want)
	}
	if !bytes.Equal(blob[14:], make([]byte, 128)) {
		t.Error("unlicensed client must report an all-zero key")
	}
}

// TestHeloOpensAtServer proves the HELO box we build is the box the far side
// expects: it decrypts under the server's long-term secret and the ephemeral
// public key carried in the clear.
func TestHeloOpensAtServer(t *testing.T) {
	_, server := testKeys(t)
	shortPK, shortSK, err := generateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	const ctr = 7

	body := encodeHelo(shortPK, ctr, &server.Public, &shortSK)
	cmd, payload, err := packetCommand(body)
	if err != nil {
		t.Fatal(err)
	}
	if cmd != cmdHelo {
		t.Fatalf("command = %q, want HELO", cmd)
	}

	var gotShortPK Key
	copy(gotShortPK[:], payload[0:KeySize])
	if gotShortPK != shortPK {
		t.Error("HELO does not carry our ephemeral public key")
	}
	if got := binary.BigEndian.Uint64(payload[KeySize : KeySize+8]); got != ctr {
		t.Errorf("nonce counter = %d, want %d", got, ctr)
	}

	plain, err := open(payload[KeySize+8:], shortNonce(noncePrefixHello, ctr), &gotShortPK, &server.Private)
	if err != nil {
		t.Fatalf("server could not open HELO: %v", err)
	}
	if !bytes.Equal(plain, make([]byte, 64)) {
		t.Errorf("HELO plaintext = %x, want 64 zero bytes", plain)
	}
}

// TestVochOpensAtServer walks the far side's verification: open the outer box
// with the session key, then the inner box with the client's long-term key,
// and check that the inner box vouches for the ephemeral key.
func TestVochOpensAtServer(t *testing.T) {
	client, server := testKeys(t)
	shortPK, shortSK, err := generateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	serverShortPK, serverShortSK, err := generateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	clientShared := precompute(&serverShortPK, &shortSK)
	serverShared := precompute(&shortPK, &serverShortSK)
	if clientShared != serverShared {
		t.Fatal("the two sides derived different session keys")
	}

	cookie := bytes.Repeat([]byte{0x5a}, cookieSize)
	const ctr = 11
	cert := certificateBlob(nil)

	body, err := encodeVoch(cookie, ctr, &client.Public, &client.Private, &shortPK, &server.Public, &clientShared, cert)
	if err != nil {
		t.Fatal(err)
	}
	_, payload, err := packetCommand(body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload[:cookieSize], cookie) {
		t.Error("VOCH does not echo the server cookie")
	}
	if got := binary.BigEndian.Uint64(payload[cookieSize : cookieSize+8]); got != ctr {
		t.Errorf("nonce counter = %d, want %d", got, ctr)
	}

	outer, err := openShared(payload[cookieSize+8:], shortNonce(noncePrefixVouch, ctr), &serverShared)
	if err != nil {
		t.Fatalf("server could not open the outer VOCH box: %v", err)
	}
	if got, want := len(outer), vouchOuterSize+len(cert); got != want {
		t.Fatalf("outer plaintext = %d bytes, want %d", got, want)
	}

	var gotLongPK Key
	copy(gotLongPK[:], outer[0:KeySize])
	if gotLongPK != client.Public {
		t.Error("VOCH does not carry the client's long-term public key")
	}
	r := outer[KeySize : KeySize+16]
	inner := outer[KeySize+16 : KeySize+16+vouchInnerSize]

	vouched, err := open(inner, longNonce(noncePrefixVoucher, r), &gotLongPK, &server.Private)
	if err != nil {
		t.Fatalf("server could not open the inner VOCH box: %v", err)
	}
	if !bytes.Equal(vouched, shortPK[:]) {
		t.Error("the inner box does not vouch for the ephemeral key")
	}

	if outer[KeySize+16+vouchInnerSize] != 1 {
		t.Error("grid VOCH must set the certificate-present flag")
	}
	if !bytes.Equal(outer[vouchOuterSize:], cert) {
		t.Error("certificate blob was not appended verbatim")
	}
}

func TestPeerVochOmitsCertificate(t *testing.T) {
	client, server := testKeys(t)
	shortPK, shortSK, err := generateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	serverShortPK, serverShortSK, err := generateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	shared := precompute(&serverShortPK, &shortSK)
	serverShared := precompute(&shortPK, &serverShortSK)

	body, err := encodeVoch(make([]byte, cookieSize), 1, &client.Public, &client.Private, &shortPK, &server.Public, &shared, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, payload, _ := packetCommand(body)
	outer, err := openShared(payload[cookieSize+8:], shortNonce(noncePrefixVouch, 1), &serverShared)
	if err != nil {
		t.Fatal(err)
	}
	if len(outer) != vouchOuterSize {
		t.Fatalf("peer outer plaintext = %d bytes, want %d", len(outer), vouchOuterSize)
	}
	if outer[vouchOuterSize-1] != 0 {
		t.Error("peer VOCH must clear the certificate-present flag")
	}
}

func TestWelcAndCookRoundTrip(t *testing.T) {
	_, server := testKeys(t)
	shortPK, shortSK, err := generateEphemeral()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := decodeWelc(make([]byte, 31)); !errors.Is(err, ErrProtocol) {
		t.Errorf("short WELC err = %v, want ErrProtocol", err)
	}
	got, err := decodeWelc(server.Public[:])
	if err != nil || got != server.Public {
		t.Fatalf("decodeWelc = %v, %v", got, err)
	}

	// Build a COOK the way a server would.
	serverShortPK, _, err := generateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	cookie := bytes.Repeat([]byte{0x3c}, cookieSize)
	var tail [16]byte
	copy(tail[:], "0123456789abcdef")
	plain := append(append([]byte{}, serverShortPK[:]...), cookie...)
	sealed := seal(plain, longNonce(noncePrefixCookie, tail[:]), &shortPK, &server.Private)
	payload := append(append([]byte{}, tail[:]...), sealed...)
	if len(payload) != cookPayloadSize {
		t.Fatalf("built COOK payload of %d bytes, want %d", len(payload), cookPayloadSize)
	}

	gotShort, gotCookie, err := decodeCook(payload, &server.Public, &shortSK)
	if err != nil {
		t.Fatalf("decodeCook: %v", err)
	}
	if gotShort != serverShortPK {
		t.Error("wrong server ephemeral key")
	}
	if !bytes.Equal(gotCookie, cookie) {
		t.Error("wrong cookie")
	}

	payload[20] ^= 0xff
	if _, _, err := decodeCook(payload, &server.Public, &shortSK); !errors.Is(err, ErrDecrypt) {
		t.Errorf("tampered COOK err = %v, want ErrDecrypt", err)
	}
}

func TestMesgRoundTrip(t *testing.T) {
	var shared [32]byte
	for i := range shared {
		shared[i] = byte(i * 3)
	}
	for _, size := range []int{0, 1, 5, 16416} {
		data := bytes.Repeat([]byte{0x7e}, size)
		body := encodeMesg(data, 42, &shared)
		_, payload, err := packetCommand(body)
		if err != nil {
			t.Fatal(err)
		}
		// The receiver uses the server-side prefix, so decode with the sender's.
		plain, err := openCounted("MESG", noncePrefixClientM, payload, &shared)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if got := int(binary.BigEndian.Uint16(plain[:2])); got != size {
			t.Errorf("size %d: length prefix = %d", size, got)
		}
		if !bytes.Equal(plain[2:], data) {
			t.Errorf("size %d: data changed", size)
		}
	}
}

func TestDecodeMesgRejectsShortAndTampered(t *testing.T) {
	var shared [32]byte
	if _, err := decodeMesg(make([]byte, 4), &shared); !errors.Is(err, ErrProtocol) {
		t.Errorf("short payload err = %v, want ErrProtocol", err)
	}
	body := encodeMesg([]byte("abc"), 1, &shared)
	_, payload, _ := packetCommand(body)
	payload[len(payload)-1] ^= 0xff
	if _, err := decodeMesg(payload, &shared); !errors.Is(err, ErrDecrypt) {
		t.Errorf("tampered err = %v, want ErrDecrypt", err)
	}
}
