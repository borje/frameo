package sdg

import (
	"encoding/hex"
	"testing"
)

func TestShortNonce(t *testing.T) {
	n := shortNonce(noncePrefixHello, 1)
	if got, want := string(n[:16]), "CurveCP-client-H"; got != want {
		t.Errorf("prefix = %q, want %q", got, want)
	}
	if got, want := hex.EncodeToString(n[16:]), "0000000000000001"; got != want {
		t.Errorf("counter = %s, want %s (big endian)", got, want)
	}
}

func TestLongNonce(t *testing.T) {
	tail := make([]byte, 16)
	for i := range tail {
		tail[i] = byte(i)
	}
	n := longNonce(noncePrefixCookie, tail)
	if got, want := string(n[:8]), "CurveCPK"; got != want {
		t.Errorf("prefix = %q, want %q", got, want)
	}
	if got, want := hex.EncodeToString(n[8:]), hex.EncodeToString(tail); got != want {
		t.Errorf("tail = %s, want %s", got, want)
	}
}
