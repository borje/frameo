// SPDX-License-Identifier: GPL-3.0-or-later

package sdg

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

// LocalProtocol is the service name a frame answers on when it is called
// directly over the local network. The relay path uses FrameoProtocol instead:
// the app asks for "framedump" through the grid and "framedump_local" on the
// LAN, and a frame accepts either name on a direct connection.
const LocalProtocol = "framedump_local"

// LocalService is the DNS-SD service type a frame advertises itself under.
// The instance name identifies the frame: see LocalInstance.
const LocalService = "_frameo._tcp"

// LocalInstance is the name a frame advertises itself under for LocalService:
// its peer id, cut to the 63 bytes a DNS label holds. The last hex digit of
// the id is therefore not advertised at all.
func LocalInstance(peer PeerID) string {
	const maxLabel = 63
	id := peer.String()
	if len(id) > maxLabel {
		return id[:maxLabel]
	}
	return id
}

// IsLocalInstance reports whether an advertised instance name is this frame.
// The comparison accepts the full peer id as well as the truncated form, since
// only the truncation seen on a real frame is known to be what frames do.
//
// A name that matches is not proof of identity and does not need to be: the
// tunnel handshake requires the device at that address to hold the peer's
// private key, so the worst an impostor can do by advertising someone else's
// name is waste a connection attempt.
func IsLocalInstance(instance string, peer PeerID) bool {
	return strings.EqualFold(instance, peer.String()) || strings.EqualFold(instance, LocalInstance(peer))
}

// DialLocal opens a direct connection to a frame on the local network, with no
// grid and no relay in the path. Everything above the socket is unchanged: it
// is the same encrypted tunnel and the same peer connection, so the returned
// Peer is used exactly like one from Grid.Connect.
//
// peer is the frame's peer id, which is also the long-term key it must present
// — a frame that answers this address with a different key is refused, so a
// stolen mDNS name gets a caller no further than the grid path would.
// protocol names the service being called, normally LocalProtocol.
//
// The service name is the one thing the direct path has to say for itself. On
// the relay path the grid tells the frame which service a caller wants before
// the tunnel is built; here there is nobody to do that, so the name travels in
// the VOCH trailer as a "protocol" property, in the slot a grid connection
// fills with its licence certificate. A frame given no property, or one it
// does not recognise, completes the handshake and then answers nothing: the
// tunnel is up but no service is behind it.
func DialLocal(ctx context.Context, ep Endpoint, peer PeerID, id *Identity, protocol string, opt *Options) (*Peer, error) {
	if id == nil {
		return nil, errors.New("sdg: no identity given")
	}
	if protocol == "" {
		return nil, errors.New("sdg: no service name given")
	}
	o := opt.withDefaults()

	nc, err := o.Dialer.DialContext(ctx, "tcp", ep.String())
	if err != nil {
		return nil, fmt.Errorf("sdg: dial frame %s: %w", ep, err)
	}
	c := newConn(nc, "local", o.Logger, o.readLimit())
	c.stepTimeout = o.StepTimeout
	stop := watchCtx(ctx, nc)
	defer stop()

	if err := c.handshake(modeLocal, &peer, &id.Public, &id.Private, protocolBlob(protocol)); err != nil {
		_ = c.close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		// A frame that hangs up part way through the handshake has decided
		// against us rather than failed to understand us: an unpaired client
		// and an unusable service name both end this way.
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: the frame closed the connection during the handshake, "+
				"which is how it refuses a caller it does not accept or a service name it does not know (%q): %w",
				ErrRefused, protocol, err)
		}
		return nil, err
	}
	o.Logger.Debug("direct connection established", "frame", ep.String(), "protocol", protocol)
	return newPeer(c, o), nil
}
