package sdg_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"frameo/internal/sdg"
	"frameo/internal/sdg/sdgtest"
)

func TestPair(t *testing.T) {
	fake := startGrid(t)

	const fullCode = "12345678"
	// The grid only ever learns the code without its last three digits.
	deviceErrs := make(chan error, 1)
	peerID, err := fake.AddPairing(fullCode[:len(fullCode)-3], sdgtest.PairingDevice(fullCode, func(err error) {
		deviceErrs <- err
	}))
	if err != nil {
		t.Fatal(err)
	}

	g := dial(t, fake)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got, err := g.Pair(ctx, fullCode)
	if err != nil {
		t.Fatalf("Pair: %v", err)
	}
	if got != sdg.PeerID(peerID) {
		t.Errorf("paired peer id = %s, want %s", got, sdg.PeerID(peerID))
	}

	select {
	case err := <-deviceErrs:
		t.Errorf("device side reported: %v", err)
	default:
	}
}

func TestPairAcceptsFormattedCode(t *testing.T) {
	fake := startGrid(t)
	const fullCode = "12345678"
	peerID, err := fake.AddPairing(fullCode[:5], sdgtest.PairingDevice(fullCode, nil))
	if err != nil {
		t.Fatal(err)
	}

	g := dial(t, fake)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// People read codes off a screen, so spacing and punctuation must not matter.
	got, err := g.Pair(ctx, "1234 - 5678")
	if err != nil {
		t.Fatalf("Pair: %v", err)
	}
	if got != sdg.PeerID(peerID) {
		t.Error("formatted code produced a different peer id")
	}
}

func TestPairWrongCode(t *testing.T) {
	fake := startGrid(t)
	// Both sides agree on the digits the grid routes by, but the device knows
	// a different full code: exactly the shape of a mistyped last digit.
	if _, err := fake.AddPairing("12345", sdgtest.PairingDevice("12345999", nil)); err != nil {
		t.Fatal(err)
	}

	g := dial(t, fake)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := g.Pair(ctx, "12345678")
	if err == nil {
		t.Fatal("pairing with the wrong code must fail")
	}
	// The device rejects our response first, so the tunnel ends before a
	// result arrives; either way pairing must not report success.
	t.Logf("wrong code reported: %v", err)
}

func TestPairRejectsUnverifiableResult(t *testing.T) {
	fake := startGrid(t)
	const fullCode = "12345678"
	if _, err := fake.AddPairing(fullCode[:5], sdgtest.WrongResultDevice(fullCode)); err != nil {
		t.Fatal(err)
	}

	g := dial(t, fake)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := g.Pair(ctx, fullCode); !errors.Is(err, sdg.ErrPairingFailed) {
		t.Errorf("err = %v, want ErrPairingFailed", err)
	}
}

func TestPairRejectsMalformedCode(t *testing.T) {
	fake := startGrid(t)
	g := dial(t, fake)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, code := range []string{"", "123", "abcdef", strings.Repeat("1", 40)} {
		if _, err := g.Pair(ctx, code); !errors.Is(err, sdg.ErrBadOTP) {
			t.Errorf("Pair(%q) err = %v, want ErrBadOTP", code, err)
		}
	}
}

func TestPairUnknownCodeRefused(t *testing.T) {
	fake := startGrid(t)
	g := dial(t, fake)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := g.Pair(ctx, "99999999"); !errors.Is(err, sdg.ErrRefused) {
		t.Errorf("err = %v, want ErrRefused", err)
	}
}
