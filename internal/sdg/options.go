// SPDX-License-Identifier: GPL-3.0-or-later

package sdg

import (
	"io"
	"log/slog"
	"net"
	"time"
)

// FrameoMaxMessage is the largest message the Frameo application exchanges,
// taken from the MdgConfiguration in the app. It bounds both what we send to a
// frame and what we accept from one.
const FrameoMaxMessage = 16416

// FrameoProtocol is the service name a Frameo frame answers on.
const FrameoProtocol = "framedump"

// Options tunes a grid connection. The zero value is usable; Dial fills in
// defaults without modifying the caller's struct.
type Options struct {
	// Dialer opens TCP connections. Defaults to a 15-second dual-stack dialer.
	Dialer *net.Dialer
	// PingInterval is how often to ping the grid. The grid drops connections
	// that go quiet, so this cannot be disabled. Defaults to 30 seconds.
	PingInterval time.Duration
	// StepTimeout bounds each individual handshake step. Defaults to 20 seconds.
	StepTimeout time.Duration
	// MaxMessage is the largest message accepted or sent on a peer connection.
	// Defaults to FrameoMaxMessage.
	MaxMessage int
	// ServerKeys, when non-empty, is the set of long-term keys a grid server
	// may present. Any other key ends the connection. Leaving it empty accepts
	// whatever answers, which is only appropriate against a test server.
	ServerKeys []Key
	// Certificate is the licence key appended to the VOCH packet of a grid
	// connection. Nil means an unlicensed client, which is what the reference
	// implementation sends and what the grid has been observed to accept.
	Certificate []byte
	// Logger receives protocol tracing. Debug level includes a hex dump of
	// every frame. Nil discards everything.
	Logger *slog.Logger
}

func (o *Options) withDefaults() *Options {
	c := &Options{}
	if o != nil {
		*c = *o
	}
	if c.Dialer == nil {
		c.Dialer = &net.Dialer{Timeout: 15 * time.Second}
	}
	if c.PingInterval <= 0 {
		c.PingInterval = 30 * time.Second
	}
	if c.StepTimeout <= 0 {
		c.StepTimeout = 20 * time.Second
	}
	if c.MaxMessage <= 0 {
		c.MaxMessage = FrameoMaxMessage
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return c
}

// readLimit is the largest frame we will read. A peer message of MaxMessage
// bytes arrives inside a packet carrying a header, a nonce and an
// authenticator, so the frame is larger than the message it delivers.
func (o *Options) readLimit() int {
	limit := o.MaxMessage + 64
	if limit > maxFrame {
		limit = maxFrame
	}
	return limit
}
