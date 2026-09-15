// SPDX-License-Identifier: GPL-3.0-or-later

package mdns

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

// TestLookupErrTellsAbsenceFromInterruption covers the two ways a lookup ends
// without a match. Only one of them is a statement about the network.
func TestLookupErrTellsAbsenceFromInterruption(t *testing.T) {
	t.Run("window ran out", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 0)
		defer cancel()
		<-ctx.Done()
		if err := lookupErr(ctx, ctx.Err()); !errors.Is(err, ErrNotFound) {
			t.Errorf("err = %v, want ErrNotFound: nothing answered in the time allowed", err)
		}
	})

	t.Run("caller gave up", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := lookupErr(ctx, ctx.Err())
		if errors.Is(err, ErrNotFound) {
			t.Errorf("err = %v, want the cancellation: an interrupted lookup found out nothing", err)
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	})

	t.Run("discovery could not run", func(t *testing.T) {
		want := errors.New("no network interface could be used")
		if err := lookupErr(context.Background(), want); !errors.Is(err, want) {
			t.Errorf("err = %v, want the failure itself rather than an absence", err)
		}
	})
}

// TestServiceStringIsDialable covers the IPv6 result: an address printed
// without brackets cannot be told from a host and port.
func TestServiceStringIsDialable(t *testing.T) {
	s := Service{
		Instance: "abc",
		Host:     "frame.local",
		Port:     60027,
		Addrs:    []netip.Addr{netip.MustParseAddr("fdfa:2018:5ea8:2eb7::1")},
	}
	if got, want := s.String(), "abc at [fdfa:2018:5ea8:2eb7::1]:60027"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}
