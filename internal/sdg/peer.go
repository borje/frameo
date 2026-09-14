package sdg

import (
	"context"
	"fmt"
	"sync"
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
	if err := p.c.sendMESG(msg); err != nil {
		p.shutdown(fmt.Errorf("sdg: peer: send: %w", err))
		return err
	}
	return nil
}

// Recv returns the next message from the peer.
func (p *Peer) Recv(ctx context.Context) ([]byte, error) {
	select {
	case msg, ok := <-p.recv:
		if !ok {
			return nil, p.closedErr()
		}
		return msg, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.done:
		// Drain anything that arrived before the connection ended, so a
		// message and the close that followed it are not reordered.
		select {
		case msg, ok := <-p.recv:
			if ok {
				return msg, nil
			}
		default:
		}
		return nil, p.closedErr()
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
