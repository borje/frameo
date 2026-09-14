//go:build live

// This test browses the real local network. Run it with:
//
//	go test -tags live ./internal/mdns -v
//
// It needs no frame: it reports whatever answers, and says so when nothing
// does, which is the useful result on a network that blocks multicast.
package mdns_test

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"frameo/internal/mdns"
)

func TestLiveBrowse(t *testing.T) {
	service := os.Getenv("MDNS_SERVICE")
	if service == "" {
		service = "_frameo._tcp"
	}
	level := slog.LevelInfo
	if testing.Verbose() {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	start := time.Now()
	found, err := mdns.Browse(ctx, service, &mdns.Options{Logger: log})
	if err != nil {
		t.Fatalf("browsing %s: %v", service, err)
	}
	t.Logf("%d instance(s) of %s in %v", len(found), service, time.Since(start).Round(time.Millisecond))
	for _, s := range found {
		t.Logf("  %s (host %s, addresses %v, answered from %v)", s, s.Host, s.Addrs, s.From)
	}
	if len(found) == 0 {
		t.Skip("nothing answered: no frame on this network, or multicast is blocked")
	}
}
