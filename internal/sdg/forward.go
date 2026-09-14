package sdg

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"frameo/internal/sdg/control"
	"google.golang.org/protobuf/proto"
)

// dialForwarded opens a socket to the relay the grid nominated and claims the
// tunnel it reserved for us. The frames exchanged here are not yet encrypted
// and carry no packet magic: they are a type byte and a protobuf. The tunnel
// handshake starts only once the relay confirms the claim.
func dialForwarded(ctx context.Context, host string, port int, tunnelID []byte, role string, o *Options) (*conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	nc, err := o.Dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("sdg: dial relay %s: %w", addr, err)
	}
	c := newConn(nc, role, o.Logger, o.readLimit())
	c.stepTimeout = o.StepTimeout
	// Cancellation has to reach this exchange too: a relay that keeps saying
	// "still trying" would otherwise hold the caller past its deadline.
	stop := watchCtx(ctx, nc)
	defer stop()

	req := &control.ForwardRemote{
		Magic:         proto.Uint32(forwardRemoteMagic),
		ProtocolMajor: proto.Uint32(protocolVersionMajor),
		ProtocolMinor: proto.Uint32(protocolVersionMinor),
		TunnelId:      tunnelID,
		Signature:     proto.String(forwardSignature),
	}
	pb, err := proto.Marshal(req)
	if err != nil {
		_ = c.close()
		return nil, fmt.Errorf("sdg: marshal forwarding request: %w", err)
	}
	if err := c.writeBody(append([]byte{msgForwardRemote}, pb...)); err != nil {
		_ = c.close()
		return nil, fmt.Errorf("sdg: send forwarding request: %w", err)
	}

	if err := awaitForwardReply(c); err != nil {
		_ = c.close()
		return nil, err
	}
	return c, nil
}

// maxHoldFrames bounds how many "still trying" frames to accept before giving
// up on a relay that is not going to connect us.
const maxHoldFrames = 64

// awaitForwardReply consumes relay frames until the tunnel is confirmed. The
// relay emits hold frames while it waits for the peer to answer; those carry
// no information beyond "still trying".
func awaitForwardReply(c *conn) error {
	holds := 0
	for {
		body, err := c.readBody()
		if err != nil {
			return fmt.Errorf("sdg: awaiting relay reply: %w", err)
		}
		switch body[0] {
		case msgForwardHold:
			if len(body) == 1 {
				if holds++; holds > maxHoldFrames {
					return fmt.Errorf("%w: the relay is still trying after %d attempts", ErrPeerTimeout, holds)
				}
				continue
			}
			return fmt.Errorf("%w: relay hold frame of %d bytes", ErrProtocol, len(body))

		case msgForwardReply:
			var reply control.ForwardReply
			if err := proto.Unmarshal(body[1:], &reply); err != nil {
				return fmt.Errorf("%w: malformed relay reply: %w", ErrProtocol, err)
			}
			if reply.GetSignature() != forwardSignature {
				return fmt.Errorf("%w: relay offered %q, want %q",
					ErrProtocol, reply.GetSignature(), forwardSignature)
			}
			return nil

		case msgForwardError:
			var fe control.ForwardError
			if err := proto.Unmarshal(body[1:], &fe); err != nil {
				return fmt.Errorf("%w: malformed relay error: %w", ErrProtocol, err)
			}
			return fmt.Errorf("sdg: %w", forwardError(fe.GetCode()))

		default:
			return fmt.Errorf("%w: unexpected relay frame type %d", ErrProtocol, body[0])
		}
	}
}
