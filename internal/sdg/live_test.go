// SPDX-License-Identifier: GPL-3.0-or-later

//go:build live

// These tests talk to the real SecureDeviceGrid. Run them with:
//
//	go test -tags live ./internal/sdg -run TestLive -v
//
// TestLiveGrid needs no device and no pairing: reaching the grid at all
// exercises the whole tunnel handshake, including whether the grid accepts an
// unlicensed client, which is the main thing that cannot be checked offline.
package sdg_test

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/borje/frameo/internal/sdg"
)

func liveOptions(t *testing.T) *sdg.Options {
	level := slog.LevelInfo
	if testing.Verbose() {
		level = slog.LevelDebug
	}
	return &sdg.Options{
		Logger:      slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})),
		StepTimeout: 20 * time.Second,
		ServerKeys:  []sdg.Key{sdg.FrameoServerKey},
	}
}

func TestLiveGrid(t *testing.T) {
	id, err := sdg.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("our peer id is %s", id.Public)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	start := time.Now()
	g, err := sdg.Dial(ctx, sdg.FrameoServers, id, liveOptions(t))
	if err != nil {
		t.Fatalf("could not reach the Frameo grid: %v", err)
	}
	defer g.Close()
	t.Logf("connected in %v, first round trip %v", time.Since(start).Round(time.Millisecond), g.RTT())

	if g.RTT() == 0 {
		t.Error("connected without measuring a round trip, which should be impossible")
	}
	// Reaching this point with the key pinned also confirms the grid still
	// presents the key the app ships.

	// Stay up long enough for the keepalive to run at least once, since a grid
	// that accepts the handshake but rejects the client later would otherwise
	// look healthy.
	select {
	case <-g.Done():
		t.Fatalf("grid dropped the connection: %v", g.Err())
	case <-time.After(35 * time.Second):
	}
	t.Logf("still connected after the first keepalive, round trip %v", g.RTT())
}
