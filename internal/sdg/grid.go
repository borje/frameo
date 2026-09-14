package sdg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"frameo/internal/sdg/control"
	"google.golang.org/protobuf/proto"
)

// Grid is a connection to the SecureDeviceGrid. It is not itself a data path:
// its job is to find peers and arrange relayed connections to them, which then
// run over their own sockets.
type Grid struct {
	c   *conn
	id  *Identity
	opt *Options

	mu      sync.Mutex
	pending map[uint32]chan *control.PeerReply
	nextID  uint32
	err     error

	done      chan struct{}
	closeOnce sync.Once

	pingMu   sync.Mutex
	pingSeq  uint32
	lastPing time.Time
	rtt      time.Duration
}

// Dial connects to the grid, racing the given servers and keeping whichever
// completes its handshake first, falling back to the rest if that one fails.
// Racing rather than picking one (at random, or by a fixed preference) means
// the nearest reachable server wins on its own, without needing to know
// distances up front. It returns once the connection is fully established.
// The identity is this client's long-term key pair; frames are paired to it.
func Dial(ctx context.Context, servers []Endpoint, id *Identity, opt *Options) (*Grid, error) {
	if len(servers) == 0 {
		return nil, errors.New("sdg: no grid servers given")
	}
	if id == nil {
		return nil, errors.New("sdg: no identity given")
	}
	o := opt.withDefaults()

	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan dialResult, len(servers))
	for _, ep := range servers {
		go func(ep Endpoint) {
			g, err := dialOne(raceCtx, ep, id, o)
			results <- dialResult{ep, g, err}
		}(ep)
	}

	var errs []error
	for received := 0; received < len(servers); received++ {
		r := <-results
		if r.err != nil {
			o.Logger.Debug("grid server unusable", "server", r.ep.String(), "err", r.err)
			errs = append(errs, fmt.Errorf("%s: %w", r.ep, r.err))
			continue
		}
		// A winner is in hand: stop every other attempt, but keep listening
		// in the background for any that were already past the point where
		// cancellation could stop them, so their connections get closed
		// instead of leaked.
		cancel()
		go closeLateWinners(results, len(servers)-received-1)
		return r.g, nil
	}
	return nil, fmt.Errorf("sdg: could not reach the grid: %w", errors.Join(errs...))
}

// dialResult is one racer's outcome, reported on Dial's results channel.
type dialResult struct {
	ep  Endpoint
	g   *Grid
	err error
}

func closeLateWinners(results <-chan dialResult, n int) {
	for range n {
		if r := <-results; r.g != nil {
			_ = r.g.Close()
		}
	}
}

func dialOne(ctx context.Context, ep Endpoint, id *Identity, o *Options) (*Grid, error) {
	nc, err := o.Dialer.DialContext(ctx, "tcp", ep.String())
	if err != nil {
		return nil, err
	}
	o.Logger.Debug("grid connected", "server", ep.String(), "addr", nc.RemoteAddr().String())

	c := newConn(nc, "grid", o.Logger, o.readLimit())
	c.stepTimeout = o.StepTimeout
	stop := watchCtx(ctx, nc)
	defer stop()

	g := &Grid{
		c:       c,
		id:      id,
		opt:     o,
		pending: make(map[uint32]chan *control.PeerReply),
		done:    make(chan struct{}),
	}

	if err := c.handshakeAny(modeGrid, o.ServerKeys, &id.Public, &id.Private, certificateBlob(o.Certificate)); err != nil {
		_ = c.close()
		return nil, err
	}
	if err := g.negotiate(); err != nil {
		_ = c.close()
		return nil, err
	}

	c.clearStepTimeout()
	go g.readLoop()
	go g.pingLoop()
	return g, nil
}

// negotiate completes the grid bring-up: exchange protocol versions, then ping
// once. The reference implementation treats the first pong as the point at
// which the connection is usable, and so does this.
func (g *Grid) negotiate() error {
	pv := &control.ProtocolVersion{
		Magic: proto.Uint32(protocolVersionMagic),
		Major: proto.Uint32(protocolVersionMajor),
		Minor: proto.Uint32(protocolVersionMinor),
	}
	if err := g.c.sendControl(msgProtocolVersion, pv); err != nil {
		return fmt.Errorf("sdg: grid: send protocol version: %w", err)
	}

	body, err := g.awaitControl(msgProtocolVersion)
	if err != nil {
		return fmt.Errorf("sdg: grid: awaiting protocol version: %w", err)
	}
	var theirs control.ProtocolVersion
	if err := proto.Unmarshal(body, &theirs); err != nil {
		return fmt.Errorf("sdg: grid: %w: malformed protocol version: %w", ErrProtocol, err)
	}
	if theirs.GetMagic() != protocolVersionMagic {
		return fmt.Errorf("sdg: grid: %w: protocol version magic %#x", ErrProtocol, theirs.GetMagic())
	}
	if theirs.GetMajor() != protocolVersionMajor || theirs.GetMinor() != protocolVersionMinor {
		return fmt.Errorf("sdg: grid: %w: unsupported grid protocol %d.%d",
			ErrProtocol, theirs.GetMajor(), theirs.GetMinor())
	}

	if err := g.sendPing(); err != nil {
		return fmt.Errorf("sdg: grid: send ping: %w", err)
	}
	body, err = g.awaitControl(msgPong)
	if err != nil {
		return fmt.Errorf("sdg: grid: awaiting the first pong: %w", err)
	}
	var pong control.Pong
	if err := proto.Unmarshal(body, &pong); err != nil {
		return fmt.Errorf("sdg: grid: %w: malformed pong: %w", ErrProtocol, err)
	}
	g.notePong(pong.GetSeq())
	return nil
}

// awaitControl reads until the grid sends the message we are waiting for.
// Anything else is handled in passing rather than treated as an error: the
// grid may volunteer a message at any time, including during bring-up, and the
// reference client dispatches on type rather than expecting a fixed order.
func (g *Grid) awaitControl(want byte) ([]byte, error) {
	for range maxBringUpMessages {
		data, err := g.c.recvMESG()
		if err != nil {
			return nil, err
		}
		if len(data) == 0 {
			continue
		}
		if data[0] == want {
			return data[1:], nil
		}
		g.opt.Logger.Debug("handling a message that arrived during bring-up", "type", data[0])
		if err := g.handle(data); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("%w: the grid never sent message %d", ErrProtocol, want)
}

// maxBringUpMessages bounds how much unrelated traffic to wade through before
// concluding the grid is not going to answer.
const maxBringUpMessages = 32

func (g *Grid) sendPing() error {
	g.pingMu.Lock()
	seq := g.pingSeq
	g.pingSeq++
	g.lastPing = time.Now()
	rtt := g.rtt
	g.pingMu.Unlock()

	ping := &control.Ping{Seq: proto.Uint32(seq)}
	if rtt > 0 {
		ping.Delay = proto.Uint32(uint32(rtt.Milliseconds()))
	}
	return g.c.sendControl(msgPing, ping)
}

func (g *Grid) notePong(seq uint32) {
	g.pingMu.Lock()
	defer g.pingMu.Unlock()
	if seq == g.pingSeq-1 && !g.lastPing.IsZero() {
		g.rtt = time.Since(g.lastPing)
	}
}

// RTT reports the last measured round trip to the grid.
func (g *Grid) RTT() time.Duration {
	g.pingMu.Lock()
	defer g.pingMu.Unlock()
	return g.rtt
}

// PeerID is this client's own address on the grid.
func (g *Grid) PeerID() PeerID { return g.id.Public }

// Done is closed when the grid connection ends, whether cleanly or with an error.
func (g *Grid) Done() <-chan struct{} { return g.done }

// Err reports why the grid connection ended, or nil if it is still up or was
// closed deliberately.
func (g *Grid) Err() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.err
}

// Close shuts down the grid connection. Peer connections already established
// keep running: they have their own sockets and do not depend on this one.
func (g *Grid) Close() error {
	g.shutdown(nil)
	return nil
}

// shutdown records the cause, wakes everyone waiting, and closes the socket. It
// runs at most once, so the first cause is the one reported.
func (g *Grid) shutdown(cause error) {
	g.closeOnce.Do(func() {
		g.mu.Lock()
		g.err = cause
		waiters := g.pending
		g.pending = nil
		g.mu.Unlock()

		for _, ch := range waiters {
			close(ch)
		}
		close(g.done)
		_ = g.c.close()
		if cause != nil {
			g.opt.Logger.Debug("grid connection lost", "err", cause)
		}
	})
}

func (g *Grid) readLoop() {
	for {
		data, err := g.c.recvMESG()
		if err != nil {
			select {
			case <-g.done:
				// Already shutting down; the read failed because we closed it.
			default:
				g.shutdown(fmt.Errorf("sdg: grid: %w", err))
			}
			return
		}
		if err := g.handle(data); err != nil {
			g.shutdown(err)
			return
		}
	}
}

func (g *Grid) handle(data []byte) error {
	if len(data) == 0 {
		return nil // The grid sends these; the reference client ignores them.
	}
	body := data[1:]
	switch data[0] {
	case msgPong:
		var pong control.Pong
		if err := proto.Unmarshal(body, &pong); err != nil {
			g.opt.Logger.Debug("malformed pong ignored", "err", err)
			return nil
		}
		g.notePong(pong.GetSeq())

	case msgRemoteReply, msgPairRemoteReply:
		var reply control.PeerReply
		if err := proto.Unmarshal(body, &reply); err != nil {
			g.opt.Logger.Debug("malformed peer reply ignored", "err", err)
			return nil
		}
		g.deliver(&reply)

	case msgIncomingCall:
		var call control.IncomingCall
		if err := proto.Unmarshal(body, &call); err != nil {
			return nil
		}
		g.opt.Logger.Debug("refusing incoming call", "protocol", call.GetProtocol())
		// This client never accepts calls, so refuse rather than leave the
		// caller waiting.
		return g.c.sendControl(msgIncomingCallResp, &control.IncomingCallReply{
			Id:     proto.Uint32(call.GetId()),
			Result: proto.Uint32(0),
		})

	default:
		g.opt.Logger.Debug("unhandled grid message", "type", data[0], "len", len(body))
	}
	return nil
}

func (g *Grid) deliver(reply *control.PeerReply) {
	g.mu.Lock()
	ch, ok := g.pending[reply.GetId()]
	if ok {
		delete(g.pending, reply.GetId())
	}
	g.mu.Unlock()
	if !ok {
		g.opt.Logger.Debug("peer reply for an unknown request", "id", reply.GetId())
		return
	}
	ch <- reply
	close(ch)
}

func (g *Grid) pingLoop() {
	t := time.NewTicker(g.opt.PingInterval)
	defer t.Stop()
	for {
		select {
		case <-g.done:
			return
		case <-t.C:
			if err := g.sendPing(); err != nil {
				g.shutdown(fmt.Errorf("sdg: grid: ping: %w", err))
				return
			}
		}
	}
}

// call sends a request that the grid answers with a PeerReply, and waits for
// that answer.
func (g *Grid) call(ctx context.Context, msgType byte, build func(id uint32) proto.Message) (*control.PeerReply, error) {
	ch := make(chan *control.PeerReply, 1)

	g.mu.Lock()
	if g.pending == nil {
		g.mu.Unlock()
		return nil, ErrClosed
	}
	id := g.nextID
	g.nextID++
	g.pending[id] = ch
	g.mu.Unlock()

	forget := func() {
		g.mu.Lock()
		delete(g.pending, id)
		g.mu.Unlock()
	}

	if err := g.c.sendControl(msgType, build(id)); err != nil {
		forget()
		return nil, fmt.Errorf("sdg: grid: send request: %w", err)
	}

	select {
	case reply, ok := <-ch:
		if !ok {
			if err := g.Err(); err != nil {
				return nil, err
			}
			return nil, ErrClosed
		}
		return reply, nil
	case <-ctx.Done():
		forget()
		return nil, ctx.Err()
	case <-g.done:
		if err := g.Err(); err != nil {
			return nil, err
		}
		return nil, ErrClosed
	}
}

// Connect opens a relayed connection to a paired peer. protocol names the
// service on the peer; for a Frameo frame it is FrameoProtocol.
func (g *Grid) Connect(ctx context.Context, peer PeerID, protocol string) (*Peer, error) {
	reply, err := g.call(ctx, msgCallRemote, func(id uint32) proto.Message {
		return &control.ConnectToPeer{
			Id:       proto.Uint32(id),
			PeerId:   proto.String(peer.String()),
			Protocol: proto.String(protocol),
		}
	})
	if err != nil {
		return nil, err
	}

	c, err := g.forwardAndHandshake(ctx, reply, modePeer, &peer)
	if err != nil {
		return nil, err
	}
	return newPeer(c, g.opt), nil
}

// forwardAndHandshake follows a successful PeerReply: open a socket to the
// relay it names, claim the tunnel, and run the tunnel handshake over it.
func (g *Grid) forwardAndHandshake(ctx context.Context, reply *control.PeerReply, m mode, expect *Key) (*conn, error) {
	if reply.GetResult() != 0 || reply.GetPeer() == nil {
		return nil, fmt.Errorf("sdg: %w (grid result %d)", ErrRefused, reply.GetResult())
	}
	info := reply.GetPeer()
	host, port := info.GetServer().GetHost(), int(info.GetServer().GetPort())
	g.opt.Logger.Debug("relay assigned", "host", host, "port", port, "tunnel", fmt.Sprintf("%x", info.GetTunnelId()))

	c, err := dialForwarded(ctx, host, port, info.GetTunnelId(), m.String(), g.opt)
	if err != nil {
		return nil, err
	}
	stop := watchCtx(ctx, c.nc)
	defer stop()

	if err := ctx.Err(); err != nil {
		_ = c.close()
		return nil, err
	}
	if err := c.handshake(m, expect, &g.id.Public, &g.id.Private, nil); err != nil {
		_ = c.close()
		return nil, err
	}
	return c, nil
}

// Pair completes a one-time pairing with a device that is showing the given
// code, and returns that device's peer id. The peer id is permanent: it
// identifies the device on every later connection, so persist it.
func (g *Grid) Pair(ctx context.Context, otp string) (PeerID, error) {
	var zero PeerID

	digits := digitsOnly(otp)
	if len(digits) < minOTPDigits || len(digits) > maxOTPDigits {
		return zero, fmt.Errorf("%w: %d digits, want %d to %d",
			ErrBadOTP, len(digits), minOTPDigits, maxOTPDigits)
	}
	// The last three digits never leave this machine. The grid uses the rest to
	// route us to the device; the full code is proven in the exchange that
	// follows, so a relay that sees the request still cannot pair.
	serverPart := digits[:len(digits)-3]

	reply, err := g.call(ctx, msgPairRemote, func(id uint32) proto.Message {
		return &control.PairRemote{Id: proto.Uint32(id), Otp: proto.String(serverPart)}
	})
	if err != nil {
		return zero, err
	}

	c, err := g.forwardAndHandshake(ctx, reply, modePairing, nil)
	if err != nil {
		return zero, err
	}
	defer c.close()

	stop := watchCtx(ctx, c.nc)
	defer stop()

	if err := runPairing(c, digits, &g.id.Public); err != nil {
		return zero, err
	}
	g.opt.Logger.Debug("pairing complete", "peer", c.serverLongPK.String())
	return c.serverLongPK, nil
}

const (
	minOTPDigits = 7
	maxOTPDigits = 31
)

// digitsOnly strips formatting from a pairing code. Codes are shown to people
// with spaces or dashes, and only the digits are significant.
func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
