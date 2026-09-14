package sdg

import "encoding/binary"

// nonceSize is the length of a crypto_box nonce.
const nonceSize = 24

// Nonce prefixes. The handshake and message nonces are a 16-character label
// plus a 64-bit counter; the two cookie-stage nonces are an 8-character label
// plus 16 bytes chosen by whoever builds the packet.
const (
	noncePrefixHello   = "CurveCP-client-H"
	noncePrefixVouch   = "CurveCP-client-I"
	noncePrefixClientM = "CurveCP-client-M"
	noncePrefixServerM = "CurveCP-server-M"
	noncePrefixReady   = "CurveCP-server-R"
	noncePrefixCookie  = "CurveCPK"
	noncePrefixVoucher = "CurveCPV"
)

// shortNonce builds a handshake or message nonce: a 16-byte label followed by
// the big-endian counter.
func shortNonce(prefix string, counter uint64) [nonceSize]byte {
	var n [nonceSize]byte
	copy(n[:16], prefix)
	binary.BigEndian.PutUint64(n[16:], counter)
	return n
}

// longNonce builds a cookie-stage nonce: an 8-byte label followed by 16 bytes
// carried in the packet.
func longNonce(prefix string, tail []byte) [nonceSize]byte {
	var n [nonceSize]byte
	copy(n[:8], prefix)
	copy(n[8:], tail)
	return n
}
