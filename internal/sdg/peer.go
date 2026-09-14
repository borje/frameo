package sdg

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Peer is an established connection to another device. It carries whole
// messages, not a byte stream: each Send produces exactly one Recv on the far
// side.
type Peer struct {
	c   *conn
	opt *Options

	recv chan []byte

	mu        sync.Mutex
	err       error
	done      chan struct{}
	closeOnce sync.Once
}

func newPeer(c *conn, o *Options) *Peer {
	c.clearStepTimeout()
	p := &Peer{
		c:    c,
		opt:  o,
		recv: make(chan []byte, 64),
		done: make(chan struct{}),
	}
	go p.readLoop()
	return p
}

// ID is the peer's long-term key, which is also its address on the grid.
func (p *Peer) ID() PeerID { return p.c.serverLongPK }

// Send transmits one message. Concurrent calls are serialised.
func (p *Peer) Send(ctx context.Context, msg []byte) error {
	if len(msg) > p.opt.MaxMessage {
		return fmt.Errorf("%w: %d bytes exceeds the %d byte limit", ErrMessageTooLarge, len(msg), p.opt.MaxMessage)
	}
	select {
	case <-p.done:
		return p.closedErr()
	default:
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// A frame that stops reading closes the send window, and a write with no
	// deadline would then block for as long as the operating system allows.
	// Bounding it by the caller's deadline is what makes a stalled transfer
	// interruptible.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(p.opt.StepTimeout)
	}
	if err := p.c.sendMESGBy(msg, deadline); err != nil {
		p.shutdown(fmt.Errorf("sdg: peer: send: %w", err))
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return err
	}
	return nil
}

// Recv returns the next message from the peer.
//
// It waits only on the message queue, never on the connection's end directly:
// the reader closes the queue as it exits, so a message that arrived just
// before the connection dropped is still delivered rather than lost to a race
// between the two.
func (p *Peer) Recv(ctx context.Context) ([]byte, error) {
	select {
	case msg, ok := <-p.recv:
		if !ok {
			return nil, p.closedErr()
		}
		return msg, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Close ends the connection.
func (p *Peer) Close() error {
	p.shutdown(nil)
	return nil
}

// Done is closed when the connection ends.
func (p *Peer) Done() <-chan struct{} { return p.done }

func (p *Peer) closedErr() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	return ErrClosed
}

func (p *Peer) shutdown(cause error) {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.err = cause
		p.mu.Unlock()
		close(p.done)
		_ = p.c.close()
	})
}

func (p *Peer) readLoop() {
	defer close(p.recv)
	for {
		msg, err := p.c.recvMESG()
		if err != nil {
			select {
			case <-p.done:
			default:
				p.shutdown(fmt.Errorf("sdg: peer: %w", err))
			}
			return
		}
		select {
		case p.recv <- msg:
		case <-p.done:
			return
		}
	}
}
