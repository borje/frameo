package sdg

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
)

// mode selects the handshake variant. The three differ only in what is
// appended to VOCH and in what happens once the tunnel is up.
type mode int

const (
	modeGrid mode = iota
	modePeer
	modePairing
)

func (m mode) String() string {
	switch m {
	case modeGrid:
		return "grid"
	case modePeer:
		return "peer"
	default:
		return "pairing"
	}
}

// conn is one encrypted tunnel: a TCP connection plus the session state the
// handshake establishes. It is shared by grid, peer and pairing connections.
type conn struct {
	nc  net.Conn
	br  *bufio.Reader
	log *slog.Logger

	role        string
	maxRead     int
	stepTimeout time.Duration

	serverLongPK Key
	shortPK      Key
	shortSK      Key
	shared       [32]byte

	sendMu sync.Mutex
	ctr    uint64
}

func newConn(nc net.Conn, role string, log *slog.Logger, maxRead int) *conn {
	return &conn{
		nc:      nc,
		br:      bufio.NewReaderSize(nc, 16*1024),
		log:     log,
		role:    role,
		maxRead: maxRead,
	}
}

// nextCtr returns the next nonce counter. One counter covers every packet this
// side encrypts on this connection: HELO, VOCH and then every MESG. The first
// value is zero.
func (c *conn) nextCtr() uint64 {
	n := c.ctr
	c.ctr++
	return n
}

// applyStepTimeout bounds the next read or write while the connection is still
// being set up. Once the handshake is done stepTimeout is cleared and the
// deadline is removed, because an idle grid connection is normal.
func (c *conn) applyStepTimeout() {
	if c.stepTimeout > 0 {
		_ = c.nc.SetDeadline(time.Now().Add(c.stepTimeout))
	}
}

// clearStepTimeout ends deadline enforcement. It must be called before any
// concurrent reader or writer starts, since a deadline covers both directions.
func (c *conn) clearStepTimeout() {
	c.stepTimeout = 0
	_ = c.nc.SetDeadline(time.Time{})
}

// readBody reads one raw frame body, with no interpretation.
func (c *conn) readBody() ([]byte, error) {
	c.applyStepTimeout()
	body, err := readFrame(c.br, c.maxRead)
	if err != nil {
		return nil, err
	}
	c.dump("recv frame", body)
	return body, nil
}

// readPacket reads one tunnel packet and returns its command and payload.
func (c *conn) readPacket() (string, []byte, error) {
	body, err := c.readBody()
	if err != nil {
		return "", nil, err
	}
	return packetCommand(body)
}

// expectPacket reads one packet and requires it to carry the given command.
func (c *conn) expectPacket(want string) ([]byte, error) {
	cmd, payload, err := c.readPacket()
	if err != nil {
		return nil, err
	}
	if cmd != want {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrProtocol, want, cmd)
	}
	return payload, nil
}

// writeBody writes one raw frame body.
func (c *conn) writeBody(body []byte) error {
	c.applyStepTimeout()
	c.dump("send frame", body)
	return writeFrame(c.nc, body)
}

// sendMESG encrypts and sends one message. It is safe for concurrent use: the
// nonce counter must advance in lockstep with the bytes on the wire, so the
// lock covers both.
func (c *conn) sendMESG(data []byte) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return c.writeBody(encodeMesg(data, c.nextCtr(), &c.shared))
}

// sendMESGBy is sendMESG with a deadline on the write itself.
func (c *conn) sendMESGBy(data []byte, deadline time.Time) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	body := encodeMesg(data, c.nextCtr(), &c.shared)
	c.dump("send frame", body)
	_ = c.nc.SetWriteDeadline(deadline)
	defer func() { _ = c.nc.SetWriteDeadline(time.Time{}) }()
	return writeFrame(c.nc, body)
}

// sendControl sends a relay control message inside the tunnel: a type byte
// followed by its protobuf.
func (c *conn) sendControl(msgType byte, m proto.Message) error {
	pb, err := proto.Marshal(m)
	if err != nil {
		return fmt.Errorf("sdg: marshal control message %d: %w", msgType, err)
	}
	return c.sendMESG(append([]byte{msgType}, pb...))
}

// recvMESG reads packets until one is a MESG and returns the data it carries.
func (c *conn) recvMESG() ([]byte, error) {
	cmd, payload, err := c.readPacket()
	if err != nil {
		return nil, err
	}
	if cmd != cmdMesg {
		return nil, fmt.Errorf("%w: expected MESG, got %s", ErrProtocol, cmd)
	}
	return decodeMesg(payload, &c.shared)
}

func (c *conn) close() error { return c.nc.Close() }

func (c *conn) dump(what string, b []byte) {
	if c.log == nil || !c.log.Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	const shown = 256
	head := b
	if len(head) > shown {
		head = head[:shown]
	}
	c.log.Debug(what, "conn", c.role, "len", len(b), "hex", hex.EncodeToString(head))
}

// handshake runs the CurveCP-style tunnel handshake to completion.
//
// expect, when non-nil, is the long-term key the remote must present; a
// mismatch means the grid connected us to the wrong device. Pairing passes nil
// because learning that key is the whole point of pairing.
//
// cert is appended to VOCH; it is non-empty only for grid connections.
func (c *conn) handshake(m mode, expect *Key, longPK, longSK *Key, cert []byte) error {
	var allowed []Key
	if expect != nil {
		allowed = []Key{*expect}
	}
	return c.handshakeAny(m, allowed, longPK, longSK, cert)
}

// handshakeAny is handshake with a set of acceptable remote keys rather than a
// single one, which is what pinning a grid's servers needs. An empty set
// accepts any key.
func (c *conn) handshakeAny(m mode, allowed []Key, longPK, longSK *Key, cert []byte) error {
	if err := c.writeBody(tellPacket()); err != nil {
		return fmt.Errorf("sdg: %s: send TELL: %w", c.role, err)
	}

	payload, err := c.expectPacket(cmdWelc)
	if err != nil {
		return fmt.Errorf("sdg: %s: awaiting WELC: %w", c.role, err)
	}
	if c.serverLongPK, err = decodeWelc(payload); err != nil {
		return fmt.Errorf("sdg: %s: %w", c.role, err)
	}
	if len(allowed) > 0 && !slices.Contains(allowed, c.serverLongPK) {
		return fmt.Errorf("sdg: %s: %w: %s is not among the %d key(s) we accept",
			c.role, ErrKeyMismatch, c.serverLongPK, len(allowed))
	}
	c.log.Debug("remote identified", "conn", c.role, "key", c.serverLongPK.String())

	pub, priv, err := generateEphemeral()
	if err != nil {
		return err
	}
	c.shortPK, c.shortSK = pub, priv

	if err := c.writeBody(encodeHelo(c.shortPK, c.nextCtr(), &c.serverLongPK, &c.shortSK)); err != nil {
		return fmt.Errorf("sdg: %s: send HELO: %w", c.role, err)
	}

	payload, err = c.expectPacket(cmdCook)
	if err != nil {
		return fmt.Errorf("sdg: %s: awaiting COOK: %w", c.role, err)
	}
	serverShortPK, cookie, err := decodeCook(payload, &c.serverLongPK, &c.shortSK)
	if err != nil {
		return fmt.Errorf("sdg: %s: %w", c.role, err)
	}
	c.shared = precompute(&serverShortPK, &c.shortSK)

	if m != modeGrid {
		cert = nil
	}
	voch, err := encodeVoch(cookie, c.nextCtr(), longPK, longSK, &c.shortPK, &c.serverLongPK, &c.shared, cert)
	if err != nil {
		return err
	}
	if err := c.writeBody(voch); err != nil {
		return fmt.Errorf("sdg: %s: send VOCH: %w", c.role, err)
	}

	payload, err = c.expectPacket(cmdRedy)
	if err != nil {
		return fmt.Errorf("sdg: %s: awaiting REDY: %w", c.role, err)
	}
	if _, err := openCounted("REDY", noncePrefixReady, payload, &c.shared); err != nil {
		return fmt.Errorf("sdg: %s: %w", c.role, err)
	}
	// The REDY payload carries the remote's own licence certificate. We are an
	// unlicensed client and have nothing to check it against, so it is ignored.
	c.log.Debug("tunnel established", "conn", c.role, "mode", m.String())
	return nil
}

// watchCtx closes nc when ctx is cancelled, so a blocked read or write fails
// promptly. The returned function stops the watcher.
func watchCtx(ctx context.Context, nc net.Conn) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = nc.Close()
		case <-done:
		}
	}()
	return func() { close(done) }
}
