package sdg

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// Packet payload sizes, counted from the end of the 8-byte packet header.
const (
	welcPayloadSize = KeySize                                   // 32
	heloPayloadSize = KeySize + 8 + (64 + boxOverhead)          // 120
	cookPayloadSize = 16 + (KeySize + cookieSize + boxOverhead) // 160
	cookieSize      = 96
	// voch is variable: the trailer is present only towards a grid or a frame's
	// local listener.
	vouchInnerSize = KeySize + boxOverhead             // 48
	vouchOuterSize = KeySize + 16 + vouchInnerSize + 1 // 97, before sealing
)

// vochProperty encodes one entry of the VOCH trailer: a length-prefixed,
// NUL-terminated name followed by a length-prefixed value. Both lengths are a
// single byte and neither counts the NUL, so a name or value of 256 bytes or
// more cannot be expressed.
//
// The trailer is how a VOCH says something about the connection beyond who is
// making it. A grid connection puts a licence certificate here; a direct
// connection to a frame on the local network puts the service it is calling
// (see DialLocal), which is the only way the frame learns that, there being no
// grid in the middle to tell it.
func vochProperty(name string, value []byte) []byte {
	b := make([]byte, 0, 1+len(name)+1+1+len(value))
	b = append(b, byte(len(name)))
	b = append(b, name...)
	b = append(b, 0)
	b = append(b, byte(len(value)))
	return append(b, value...)
}

// certificateBlob is the licence key a client appends to its VOCH when talking
// to a grid server. An unlicensed client reports an all-zero key, which is
// what the original library does and what the grid accepts.
func certificateBlob(key []byte) []byte {
	const keyLen = 128
	value := make([]byte, keyLen)
	copy(value, key[:min(len(key), keyLen)])
	return vochProperty("certificate", value)
}

// protocolBlob is the service name a caller appends to its VOCH when
// connecting straight to a frame on the local network.
func protocolBlob(protocol string) []byte {
	return vochProperty("protocol", []byte(protocol))
}

// decodeWelc extracts the server's long-term public key.
func decodeWelc(payload []byte) (Key, error) {
	var k Key
	if len(payload) < welcPayloadSize {
		return k, errShort("WELC", len(payload), welcPayloadSize)
	}
	copy(k[:], payload)
	return k, nil
}

// encodeHelo builds the HELO packet body: our ephemeral public key, the nonce
// counter, and a box of 64 zero bytes proving we hold the matching secret.
func encodeHelo(shortPK Key, ctr uint64, serverLongPK, shortSK *Key) []byte {
	body := buildPacket(cmdHelo, heloPayloadSize)
	p := body[headerSize:]
	copy(p[0:KeySize], shortPK[:])
	binary.BigEndian.PutUint64(p[KeySize:KeySize+8], ctr)
	sealed := seal(make([]byte, 64), shortNonce(noncePrefixHello, ctr), serverLongPK, shortSK)
	copy(p[KeySize+8:], sealed)
	return body
}

// decodeCook opens the server's cookie packet, yielding its ephemeral public
// key and the opaque cookie we must echo in VOCH.
func decodeCook(payload []byte, serverLongPK, shortSK *Key) (serverShortPK Key, cookie []byte, err error) {
	if len(payload) < cookPayloadSize {
		return serverShortPK, nil, errShort("COOK", len(payload), cookPayloadSize)
	}
	nonce := longNonce(noncePrefixCookie, payload[0:16])
	plain, err := open(payload[16:cookPayloadSize], nonce, serverLongPK, shortSK)
	if err != nil {
		return serverShortPK, nil, fmt.Errorf("COOK: %w", err)
	}
	copy(serverShortPK[:], plain[0:KeySize])
	cookie = make([]byte, cookieSize)
	copy(cookie, plain[KeySize:])
	return serverShortPK, cookie, nil
}

// encodeVoch builds the VOCH packet body. The outer box, sealed with the
// session key, carries our long-term identity plus an inner box that binds our
// ephemeral key to it, and then a trailer: a count of the properties that
// follow, and the properties themselves. Only one property is ever sent, so
// the count is 0 or 1; whether a larger count is accepted has not been tried.
func encodeVoch(cookie []byte, ctr uint64, longPK, longSK, shortPK, serverLongPK *Key, shared *[32]byte, props []byte) ([]byte, error) {
	var r [16]byte
	if _, err := rand.Read(r[:]); err != nil {
		return nil, fmt.Errorf("sdg: VOCH nonce: %w", err)
	}
	return encodeVochWith(cookie, ctr, r, longPK, longSK, shortPK, serverLongPK, shared, props), nil
}

// encodeVochWith is encodeVoch with the inner box's nonce supplied, so the
// packet can be compared against a known-good one.
func encodeVochWith(cookie []byte, ctr uint64, r [16]byte, longPK, longSK, shortPK, serverLongPK *Key, shared *[32]byte, props []byte) []byte {
	inner := seal(shortPK[:], longNonce(noncePrefixVoucher, r[:]), serverLongPK, longSK)

	outer := make([]byte, 0, vouchOuterSize+len(props))
	outer = append(outer, longPK[:]...)
	outer = append(outer, r[:]...)
	outer = append(outer, inner...)
	if len(props) > 0 {
		outer = append(outer, 1)
		outer = append(outer, props...)
	} else {
		outer = append(outer, 0)
	}
	sealed := sealShared(outer, shortNonce(noncePrefixVouch, ctr), shared)

	body := buildPacket(cmdVoch, cookieSize+8+len(sealed))
	p := body[headerSize:]
	copy(p[0:cookieSize], cookie)
	binary.BigEndian.PutUint64(p[cookieSize:cookieSize+8], ctr)
	copy(p[cookieSize+8:], sealed)
	return body
}

// openCounted decrypts a payload that begins with an 8-byte nonce counter,
// which covers REDY and MESG alike. The counter is the sender's, so it is read
// from the packet rather than tracked.
func openCounted(what, prefix string, payload []byte, shared *[32]byte) ([]byte, error) {
	if len(payload) < 8+boxOverhead {
		return nil, errShort(what, len(payload), 8+boxOverhead)
	}
	ctr := binary.BigEndian.Uint64(payload[0:8])
	plain, err := openShared(payload[8:], shortNonce(prefix, ctr), shared)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	return plain, nil
}

// encodeMesg builds an encrypted message packet. The plaintext is the data
// prefixed by its own 16-bit length, which is how the receiver finds the end of
// the message inside the box.
func encodeMesg(data []byte, ctr uint64, shared *[32]byte) []byte {
	plain := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(plain, uint16(len(data)))
	copy(plain[2:], data)
	sealed := sealShared(plain, shortNonce(noncePrefixClientM, ctr), shared)

	body := buildPacket(cmdMesg, 8+len(sealed))
	p := body[headerSize:]
	binary.BigEndian.PutUint64(p[0:8], ctr)
	copy(p[8:], sealed)
	return body
}

// decodeMesg opens a message packet and returns the data it carries.
func decodeMesg(payload []byte, shared *[32]byte) ([]byte, error) {
	plain, err := openCounted("MESG", noncePrefixServerM, payload, shared)
	if err != nil {
		return nil, err
	}
	if len(plain) < 2 {
		return nil, errShort("MESG plaintext", len(plain), 2)
	}
	n := int(binary.BigEndian.Uint16(plain[0:2]))
	if n > len(plain)-2 {
		return nil, fmt.Errorf("%w: MESG claims %d bytes but carries %d", ErrProtocol, n, len(plain)-2)
	}
	return plain[2 : 2+n], nil
}
