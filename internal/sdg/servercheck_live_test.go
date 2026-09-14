//go:build live

package sdg_test

import (
	"context"
	"testing"
	"time"

	"frameo/internal/sdg"
)

// TestLiveEveryServerIsFrameo dials each configured grid server on its own and
// requires it to present the pinned key. It is how a stale address in the
// fallback list gets caught, rather than being discovered as a confusing
// failure later.
func TestLiveEveryServerIsFrameo(t *testing.T) {
	id, err := sdg.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	for _, ep := range sdg.FrameoServers {
		t.Run(ep.String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			g, err := sdg.Dial(ctx, []sdg.Endpoint{ep}, id, &sdg.Options{
				ServerKeys: []sdg.Key{sdg.FrameoServerKey},
			})
			if err != nil {
				t.Errorf("not usable: %v", err)
				return
			}
			defer g.Close()
			t.Logf("ok, round trip %v", g.RTT())
		})
	}
}
