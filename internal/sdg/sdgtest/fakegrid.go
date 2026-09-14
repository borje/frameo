package sdgtest

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"

	"frameo/internal/sdg/control"
	"google.golang.org/protobuf/proto"
)

// PeerHandler runs the device side of a relayed connection once its tunnel is
// established.
type PeerHandler func(*Tunnel)

// Grid is an in-process SecureDeviceGrid: a grid listener that answers control
// messages and a relay listener that joins clients to registered devices.
type Grid struct {
	Long KeyPair

	// RefuseCalls makes every connection request come back refused.
	RefuseCalls bool
	// ForwardErrorCode, when non-zero, makes the relay reject the tunnel claim
	// with that error code instead of accepting it.
	ForwardErrorCode uint32
	// HoldFrames is how many "still trying" frames the relay emits before it
	// confirms a tunnel claim.
	HoldFrames int
	// MisrouteTo, when set, makes the grid connect every caller to this device
	// whatever peer id they asked for, standing in for a compromised grid.
	MisrouteTo *Key

	gridLn  net.Listener
	relayLn net.Listener

	mu      sync.Mutex
	devices map[string]*device // by peer id, lowercase hex
	otps    map[string]*device // by the digits the grid is given
	tunnels map[string]*device // by tunnel id
	nextTun int
	errs    []error
	closed  bool

	wg sync.WaitGroup
}

type device struct {
	long    KeyPair
	handler PeerHandler
}

// NewGrid starts a grid and its relay on the loopback interface.
func NewGrid() (*Grid, error) {
	long, err := NewKeyPair()
	if err != nil {
		return nil, err
	}
	g := &Grid{
		Long:    long,
		devices: map[string]*device{},
		otps:    map[string]*device{},
		tunnels: map[string]*device{},
	}
	if g.gridLn, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		return nil, err
	}
	if g.relayLn, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		_ = g.gridLn.Close()
		return nil, err
	}
	g.wg.Add(2)
	go g.serve(g.gridLn, g.handleGrid)
	go g.serve(g.relayLn, g.handleRelay)
	return g, nil
}

// Addr is the grid's listening address.
func (g *Grid) Addr() string { return g.gridLn.Addr().String() }

// Host and Port split the grid address for use as an endpoint.
func (g *Grid) Host() string {
	h, _, _ := net.SplitHostPort(g.Addr())
	return h
}

func (g *Grid) Port() int {
	_, p, _ := net.SplitHostPort(g.Addr())
	n, _ := strconv.Atoi(p)
	return n
}

// AddDevice registers a device that clients may connect to, and returns its
// peer id.
func (g *Grid) AddDevice(h PeerHandler) (Key, error) {
	long, err := NewKeyPair()
	if err != nil {
		return Key{}, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.devices[hex.EncodeToString(long.Public[:])] = &device{long: long, handler: h}
	return long.Public, nil
}

// AddPairing registers a device reachable by pairing code. The grid is only
// given the code without its last three digits, matching the real protocol, so
// that is the key used here.
func (g *Grid) AddPairing(otpForGrid string, h PeerHandler) (Key, error) {
	long, err := NewKeyPair()
	if err != nil {
		return Key{}, err
	}
	d := &device{long: long, handler: h}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.otps[otpForGrid] = d
	g.devices[hex.EncodeToString(long.Public[:])] = d
	return long.Public, nil
}

// Close shuts the grid down and returns any error its goroutines recorded.
func (g *Grid) Close() error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	g.mu.Unlock()

	_ = g.gridLn.Close()
	_ = g.relayLn.Close()
	g.wg.Wait()

	g.mu.Lock()
	defer g.mu.Unlock()
	return errors.Join(g.errs...)
}

// Errs returns the errors recorded so far without shutting down.
func (g *Grid) Errs() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return errors.Join(g.errs...)
}

func (g *Grid) record(err error) {
	// A client that hangs up mid-handshake is exercising a legitimate path,
	// such as rejecting a device whose key does not match. That is not a
	// server-side fault, so it must not fail the test that provoked it.
	if err == nil ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.closed {
		g.errs = append(g.errs, err)
	}
}

func (g *Grid) serve(ln net.Listener, handle func(net.Conn)) {
	defer g.wg.Done()
	for {
		nc, err := ln.Accept()
		if err != nil {
			return
		}
		g.wg.Add(1)
		go func() {
			defer g.wg.Done()
			defer nc.Close()
			handle(nc)
		}()
	}
}

// handleGrid serves one client's grid connection.
func (g *Grid) handleGrid(nc net.Conn) {
	t := newTunnel(nc, g.Long)
	if err := t.handshake(true); err != nil {
		g.record(fmt.Errorf("grid handshake: %w", err))
		return
	}
	for {
		data, err := t.Recv()
		if err != nil {
			return
		}
		if len(data) == 0 {
			continue
		}
		if err := g.handleControl(t, data); err != nil {
			g.record(err)
			return
		}
	}
}

func (g *Grid) handleControl(t *Tunnel, data []byte) error {
	body := data[1:]
	switch data[0] {
	case 1: // protocol version
		var pv control.ProtocolVersion
		if err := proto.Unmarshal(body, &pv); err != nil {
			return fmt.Errorf("grid: protocol version: %w", err)
		}
		if pv.GetMagic() != 0xF09D8CA8 {
			return fmt.Errorf("grid: protocol version magic %#x", pv.GetMagic())
		}
		return g.sendControl(t, 1, &control.ProtocolVersion{
			Magic: proto.Uint32(0xF09D8CA8),
			Major: proto.Uint32(1),
			Minor: proto.Uint32(0),
		})

	case 4: // ping
		var ping control.Ping
		if err := proto.Unmarshal(body, &ping); err != nil {
			return fmt.Errorf("grid: ping: %w", err)
		}
		return g.sendControl(t, 5, &control.Pong{Seq: proto.Uint32(ping.GetSeq())})

	case 10: // call remote
		var req control.ConnectToPeer
		if err := proto.Unmarshal(body, &req); err != nil {
			return fmt.Errorf("grid: call remote: %w", err)
		}
		g.mu.Lock()
		d := g.devices[req.GetPeerId()]
		if g.MisrouteTo != nil {
			d = g.devices[hex.EncodeToString(g.MisrouteTo[:])]
		}
		g.mu.Unlock()
		return g.replyPeer(t, 11, req.GetId(), d)

	case 32: // pair remote
		var req control.PairRemote
		if err := proto.Unmarshal(body, &req); err != nil {
			return fmt.Errorf("grid: pair remote: %w", err)
		}
		g.mu.Lock()
		d := g.otps[req.GetOtp()]
		g.mu.Unlock()
		return g.replyPeer(t, 33, req.GetId(), d)

	default:
		return nil
	}
}

func (g *Grid) replyPeer(t *Tunnel, msgType byte, id uint32, d *device) error {
	if d == nil || g.RefuseCalls {
		return g.sendControl(t, msgType, &control.PeerReply{
			Id:     proto.Uint32(id),
			Result: proto.Uint32(1),
		})
	}

	g.mu.Lock()
	g.nextTun++
	tun := fmt.Sprintf("tunnel-%d", g.nextTun)
	g.tunnels[tun] = d
	g.mu.Unlock()

	return g.sendControl(t, msgType, &control.PeerReply{
		Id:     proto.Uint32(id),
		Result: proto.Uint32(0),
		Peer: &control.PeerInfo{
			PeerId: proto.String(hex.EncodeToString(d.long.Public[:])),
			Server: &control.PeerInfo_ForwardHost{
				Host: proto.String(g.relayHost()),
				Port: proto.Uint32(uint32(g.relayPort())),
			},
			TunnelId: []byte(tun),
		},
	})
}

func (g *Grid) relayHost() string {
	h, _, _ := net.SplitHostPort(g.relayLn.Addr().String())
	return h
}

func (g *Grid) relayPort() int {
	_, p, _ := net.SplitHostPort(g.relayLn.Addr().String())
	n, _ := strconv.Atoi(p)
	return n
}

func (g *Grid) sendControl(t *Tunnel, msgType byte, m proto.Message) error {
	pb, err := proto.Marshal(m)
	if err != nil {
		return err
	}
	return t.Send(append([]byte{msgType}, pb...))
}

// handleRelay serves one client's connection to the relay: validate the tunnel
// claim, then become the device at the other end of it.
func (g *Grid) handleRelay(nc net.Conn) {
	t := newTunnel(nc, KeyPair{})

	body, err := t.readFrame()
	if err != nil {
		g.record(fmt.Errorf("relay: read claim: %w", err))
		return
	}
	if len(body) == 0 || body[0] != 0 {
		g.record(fmt.Errorf("relay: expected a forwarding request, got type %v", body))
		return
	}
	var req control.ForwardRemote
	if err := proto.Unmarshal(body[1:], &req); err != nil {
		g.record(fmt.Errorf("relay: malformed forwarding request: %w", err))
		return
	}
	if req.GetMagic() != 0xF09D8C95 {
		g.record(fmt.Errorf("relay: forwarding magic %#x", req.GetMagic()))
		return
	}
	if req.GetSignature() != "Mdg-NaCl/binary" {
		g.record(fmt.Errorf("relay: forwarding signature %q", req.GetSignature()))
		return
	}

	for range g.HoldFrames {
		if err := t.writeFrame([]byte{1}); err != nil {
			return
		}
	}

	if g.ForwardErrorCode != 0 {
		pb, _ := proto.Marshal(&control.ForwardError{Code: proto.Uint32(g.ForwardErrorCode)})
		_ = t.writeFrame(append([]byte{3}, pb...))
		return
	}

	g.mu.Lock()
	d := g.tunnels[string(req.GetTunnelId())]
	delete(g.tunnels, string(req.GetTunnelId()))
	g.mu.Unlock()
	if d == nil {
		pb, _ := proto.Marshal(&control.ForwardError{Code: proto.Uint32(3)})
		_ = t.writeFrame(append([]byte{3}, pb...))
		return
	}

	pb, _ := proto.Marshal(&control.ForwardReply{Signature: proto.String("Mdg-NaCl/binary")})
	if err := t.writeFrame(append([]byte{2}, pb...)); err != nil {
		return
	}

	t.long = d.long
	if err := t.handshake(false); err != nil {
		g.record(fmt.Errorf("relay: device handshake: %w", err))
		return
	}
	d.handler(t)
}
