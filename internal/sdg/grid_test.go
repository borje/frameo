// SPDX-License-Identifier: GPL-3.0-or-later

package sdg_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/borje/unframeo/internal/sdg"
	"github.com/borje/unframeo/internal/sdg/sdgtest"
)

func testOptions() *sdg.Options {
	return &sdg.Options{
		PingInterval: 50 * time.Millisecond,
		StepTimeout:  5 * time.Second,
	}
}

// startGrid brings up an in-process grid and fails the test if any of its
// server-side checks were violated.
func startGrid(t *testing.T) *sdgtest.Grid {
	t.Helper()
	g, err := sdgtest.NewGrid()
	if err != nil {
		t.Fatalf("start fake grid: %v", err)
	}
	t.Cleanup(func() {
		if err := g.Close(); err != nil {
			t.Errorf("fake grid reported: %v", err)
		}
	})
	return g
}

func endpoints(g *sdgtest.Grid) []sdg.Endpoint {
	return []sdg.Endpoint{{Host: g.Host(), Port: g.Port()}}
}

func dial(t *testing.T, fake *sdgtest.Grid) *sdg.Grid {
	t.Helper()
	id, err := sdg.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	g, err := sdg.Dial(ctx, endpoints(fake), id, testOptions())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g
}

func TestDial(t *testing.T) {
	fake := startGrid(t)
	g := dial(t, fake)

	// Reaching this point means the version exchange and the first ping both
	// completed, which is what the reference client treats as connected.
	select {
	case <-g.Done():
		t.Fatalf("grid closed immediately: %v", g.Err())
	default:
	}
}

func TestDialKeepsPinging(t *testing.T) {
	fake := startGrid(t)
	g := dial(t, fake)

	deadline := time.After(3 * time.Second)
	for g.RTT() == 0 {
		select {
		case <-deadline:
			t.Fatal("no ping round trip was measured")
		case <-g.Done():
			t.Fatalf("grid closed: %v", g.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestDialRejectsEmptyServerList(t *testing.T) {
	id, _ := sdg.NewIdentity()
	if _, err := sdg.Dial(context.Background(), nil, id, nil); err == nil {
		t.Error("want an error with no servers")
	}
}

func TestDialTriesEveryServer(t *testing.T) {
	fake := startGrid(t)
	id, _ := sdg.NewIdentity()

	servers := []sdg.Endpoint{
		{Host: "127.0.0.1", Port: 1}, // nothing listens here
		{Host: fake.Host(), Port: fake.Port()},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	g, err := sdg.Dial(ctx, servers, id, testOptions())
	if err != nil {
		t.Fatalf("Dial should have fallen through to the working server: %v", err)
	}
	_ = g.Close()
}

func TestDialCancelled(t *testing.T) {
	fake := startGrid(t)
	id, _ := sdg.NewIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sdg.Dial(ctx, endpoints(fake), id, testOptions()); err == nil {
		t.Error("want an error from a cancelled context")
	}
}

func TestConnectEcho(t *testing.T) {
	fake := startGrid(t)
	peerID, err := fake.AddDevice(sdgtest.EchoDevice())
	if err != nil {
		t.Fatal(err)
	}
	g := dial(t, fake)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p, err := g.Connect(ctx, sdg.PeerID(peerID), "framedump")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()

	if got := p.ID(); got != sdg.PeerID(peerID) {
		t.Errorf("peer id = %s, want %s", got, sdg.PeerID(peerID))
	}

	for _, size := range []int{1, 100, 16416} {
		msg := bytes.Repeat([]byte{byte(size)}, size)
		if err := p.Send(ctx, msg); err != nil {
			t.Fatalf("Send %d bytes: %v", size, err)
		}
		got, err := p.Recv(ctx)
		if err != nil {
			t.Fatalf("Recv %d bytes: %v", size, err)
		}
		if !bytes.Equal(got, msg) {
			t.Errorf("echo of %d bytes came back changed", size)
		}
	}
}

func TestSendRejectsOversizeMessage(t *testing.T) {
	fake := startGrid(t)
	peerID, _ := fake.AddDevice(sdgtest.EchoDevice())
	g := dial(t, fake)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p, err := g.Connect(ctx, sdg.PeerID(peerID), "framedump")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	err = p.Send(ctx, make([]byte, sdg.FrameoMaxMessage+1))
	if !errors.Is(err, sdg.ErrMessageTooLarge) {
		t.Errorf("err = %v, want ErrMessageTooLarge", err)
	}
}

func TestConnectUnknownPeerRefused(t *testing.T) {
	fake := startGrid(t)
	g := dial(t, fake)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var unknown sdg.PeerID
	unknown[0] = 0xaa
	if _, err := g.Connect(ctx, unknown, "framedump"); !errors.Is(err, sdg.ErrRefused) {
		t.Errorf("err = %v, want ErrRefused", err)
	}
}

func TestConnectRelayError(t *testing.T) {
	fake := startGrid(t)
	fake.ForwardErrorCode = 4 // the peer never answered
	peerID, _ := fake.AddDevice(sdgtest.EchoDevice())
	g := dial(t, fake)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := g.Connect(ctx, sdg.PeerID(peerID), "framedump"); !errors.Is(err, sdg.ErrPeerTimeout) {
		t.Errorf("err = %v, want ErrPeerTimeout", err)
	}
}

func TestConnectToleratesRelayHoldFrames(t *testing.T) {
	fake := startGrid(t)
	fake.HoldFrames = 3
	peerID, _ := fake.AddDevice(sdgtest.EchoDevice())
	g := dial(t, fake)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p, err := g.Connect(ctx, sdg.PeerID(peerID), "framedump")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()

	if err := p.Send(ctx, []byte("hi")); err != nil {
		t.Fatal(err)
	}
	if got, err := p.Recv(ctx); err != nil || string(got) != "hi" {
		t.Errorf("Recv = %q, %v", got, err)
	}
}

// TestConnectWrongKey covers a grid that joins us to a device other than the
// one we asked for. The client must notice, because the peer id is the only
// thing that says this is our frame.
func TestConnectWrongKey(t *testing.T) {
	fake := startGrid(t)
	wanted, err := fake.AddDevice(sdgtest.EchoDevice())
	if err != nil {
		t.Fatal(err)
	}
	other, err := fake.AddDevice(sdgtest.EchoDevice())
	if err != nil {
		t.Fatal(err)
	}
	fake.MisrouteTo = &other
	g := dial(t, fake)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := g.Connect(ctx, sdg.PeerID(wanted), "framedump"); !errors.Is(err, sdg.ErrKeyMismatch) {
		t.Errorf("err = %v, want ErrKeyMismatch", err)
	}
}

func TestGridCloseFailsPendingWork(t *testing.T) {
	fake := startGrid(t)
	g := dial(t, fake)

	_ = g.Close()
	select {
	case <-g.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Done was not closed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var id sdg.PeerID
	if _, err := g.Connect(ctx, id, "framedump"); !errors.Is(err, sdg.ErrClosed) {
		t.Errorf("err = %v, want ErrClosed", err)
	}
}

func TestPeerOutlivesGrid(t *testing.T) {
	fake := startGrid(t)
	peerID, _ := fake.AddDevice(sdgtest.EchoDevice())
	g := dial(t, fake)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p, err := g.Connect(ctx, sdg.PeerID(peerID), "framedump")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// The grid arranges connections; it does not carry them. Closing it must
	// leave an established peer connection working.
	_ = g.Close()

	if err := p.Send(ctx, []byte("still here")); err != nil {
		t.Fatalf("Send after closing the grid: %v", err)
	}
	got, err := p.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv after closing the grid: %v", err)
	}
	if string(got) != "still here" {
		t.Errorf("Recv = %q", got)
	}
}

func TestConcurrentConnects(t *testing.T) {
	fake := startGrid(t)
	var ids []sdg.PeerID
	for range 4 {
		id, err := fake.AddDevice(sdgtest.EchoDevice())
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, sdg.PeerID(id))
	}
	g := dial(t, fake)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := g.Connect(ctx, id, "framedump")
			if err != nil {
				t.Errorf("Connect %s: %v", id, err)
				return
			}
			defer p.Close()
			if err := p.Send(ctx, []byte(id.String())); err != nil {
				t.Errorf("Send: %v", err)
				return
			}
			got, err := p.Recv(ctx)
			if err != nil {
				t.Errorf("Recv: %v", err)
				return
			}
			if string(got) != id.String() {
				t.Errorf("wrong echo for %s", id)
			}
		}()
	}
	wg.Wait()
}

// TestRecvDeliversMessagesSentBeforeClose covers the race between a message
// arriving and the connection ending: both become ready at once, and the
// message must still be delivered rather than replaced by a closed error.
func TestRecvDeliversMessagesSentBeforeClose(t *testing.T) {
	fake := startGrid(t)
	peerID, err := fake.AddDevice(func(tun *sdgtest.Tunnel) {
		if _, err := tun.Recv(); err != nil {
			return
		}
		// Answer and hang up immediately.
		_ = tun.Send([]byte("last words"))
	})
	if err != nil {
		t.Fatal(err)
	}
	g := dial(t, fake)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p, err := g.Connect(ctx, sdg.PeerID(peerID), "framedump")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	if err := p.Send(ctx, []byte("anything")); err != nil {
		t.Fatal(err)
	}
	got, err := p.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if string(got) != "last words" {
		t.Errorf("Recv = %q, want the message sent before the connection ended", got)
	}
}
