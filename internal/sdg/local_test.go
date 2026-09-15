// SPDX-License-Identifier: GPL-3.0-or-later

package sdg_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/borje/unframeo/internal/sdg"
	"github.com/borje/unframeo/internal/sdg/sdgtest"
)

// testIdentity is a fresh client identity for one test.
func testIdentity(t *testing.T) *sdg.Identity {
	t.Helper()
	id, err := sdg.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// localDevice starts a device listening for direct connections and returns it
// with its address.
func localDevice(t *testing.T, h sdgtest.PeerHandler) (*sdgtest.LocalDevice, sdg.Endpoint, sdg.PeerID) {
	t.Helper()
	d, err := sdgtest.NewLocalDevice(h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Errorf("closing the device: %v", err)
		}
		if err := d.Errs(); err != nil {
			t.Errorf("device reported: %v", err)
		}
	})
	return d, sdg.Endpoint{Host: d.Host(), Port: d.Port()}, sdg.PeerID(d.Long.Public)
}

func TestDialLocalCarriesMessages(t *testing.T) {
	_, ep, peer := localDevice(t, sdgtest.EchoDevice())
	id := testIdentity(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	p, err := sdg.DialLocal(ctx, ep, peer, id, sdg.LocalProtocol, testOptions())
	if err != nil {
		t.Fatalf("DialLocal: %v", err)
	}
	defer p.Close()

	if p.ID() != peer {
		t.Errorf("connected to %s, want %s", p.ID(), peer)
	}
	if err := p.Send(ctx, []byte("hello frame")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got, err := p.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if string(got) != "hello frame" {
		t.Errorf("got %q back", got)
	}
}

// TestDialLocalRejectsAnotherDevice covers the one thing discovery cannot be
// trusted with: an mDNS name is not proof of identity, so a device answering
// at the advertised address with a different key must be refused.
func TestDialLocalRejectsAnotherDevice(t *testing.T) {
	_, ep, _ := localDevice(t, sdgtest.EchoDevice())
	other, err := sdgtest.NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = sdg.DialLocal(ctx, ep, sdg.PeerID(other.Public), testIdentity(t), sdg.LocalProtocol, testOptions())
	if !errors.Is(err, sdg.ErrKeyMismatch) {
		t.Fatalf("connecting to the wrong device gave %v, want ErrKeyMismatch", err)
	}
}

// TestDialLocalRefusedService covers a frame that hangs up during the
// handshake, which is how it turns a caller away.
func TestDialLocalRefusedService(t *testing.T) {
	d, ep, peer := localDevice(t, sdgtest.EchoDevice())
	d.Protocols = nil // answers on nothing at all

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The refusal is not in the handshake itself: the tunnel comes up and then
	// nothing is behind it, exactly as a real frame behaves with a service
	// name it does not know.
	p, err := sdg.DialLocal(ctx, ep, peer, testIdentity(t), "not-a-service", testOptions())
	if err != nil {
		t.Fatalf("DialLocal: %v", err)
	}
	defer p.Close()

	short, cancelShort := context.WithTimeout(ctx, 2*time.Second)
	defer cancelShort()
	if _, err := p.Recv(short); err == nil {
		t.Fatal("a frame with no such service answered anyway")
	}
}

func TestDialLocalNeedsAService(t *testing.T) {
	_, ep, peer := localDevice(t, sdgtest.EchoDevice())
	_, err := sdg.DialLocal(context.Background(), ep, peer, testIdentity(t), "", testOptions())
	if err == nil {
		t.Fatal("dialling with no service name was allowed")
	}
}

func TestLocalInstanceIsTheTruncatedPeerID(t *testing.T) {
	peer, err := sdg.ParseKey("f77db3505d636efcf03d6b89e7eabb757eb7a781cb284c131e9468f96a53fa48")
	if err != nil {
		t.Fatal(err)
	}
	const advertised = "f77db3505d636efcf03d6b89e7eabb757eb7a781cb284c131e9468f96a53fa4"

	if got := sdg.LocalInstance(peer); got != advertised {
		t.Errorf("LocalInstance = %q, want the id without its last digit", got)
	}
	if len(advertised) != 63 {
		t.Errorf("the advertised name is %d characters, not a full DNS label", len(advertised))
	}
	for _, name := range []string{advertised, peer.String(), "F77DB3505D636EFCF03D6B89E7EABB757EB7A781CB284C131E9468F96A53FA4"} {
		if !sdg.IsLocalInstance(name, peer) {
			t.Errorf("IsLocalInstance(%q) = false", name)
		}
	}
	for _, name := range []string{"", "f77db350", advertised + "0000", "0" + advertised[1:]} {
		if sdg.IsLocalInstance(name, peer) {
			t.Errorf("IsLocalInstance(%q) = true", name)
		}
	}
}
