package frameo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"frameo/internal/frameo/pb"
	"google.golang.org/protobuf/proto"
)

// segmentSize is how much file data goes in one transfer segment. It leaves
// room for the segment's own encoding inside one transport message, so photo
// data never has to be split a second time.
const segmentSize = 16000

// AckTimeout is how long to wait for the frame to confirm a transfer. It is
// generous because the frame writes the file to storage before answering.
const AckTimeout = 120 * time.Second

// Transport is the message pipe to the frame, satisfied by a peer connection.
type Transport interface {
	Send(ctx context.Context, msg []byte) error
	Recv(ctx context.Context) ([]byte, error)
	Close() error
}

// Client talks to one frame.
type Client struct {
	t   Transport
	log *slog.Logger
	r   *reassembler

	frames chan Frame
	nextID atomic.Int64

	mu        sync.Mutex
	err       error
	done      chan struct{}
	closeOnce sync.Once
}

// NewClient starts talking to a frame over an established connection. It takes
// ownership of the connection: closing the client closes it.
func NewClient(t Transport, log *slog.Logger) *Client {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	c := &Client{
		t:      t,
		log:    log,
		r:      newReassembler(64 << 20),
		frames: make(chan Frame, 16),
		done:   make(chan struct{}),
	}
	c.nextID.Store(time.Now().UnixMilli())
	go c.readLoop()
	return c
}

// Close ends the conversation and the underlying connection.
func (c *Client) Close() error {
	c.shutdown(nil)
	return c.t.Close()
}

func (c *Client) shutdown(cause error) {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.err = cause
		c.mu.Unlock()
		close(c.done)
	})
}

func (c *Client) closedErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	return errors.New("frameo: connection closed")
}

// newID mints an identifier for a transfer or an acknowledgement. The frame
// keys transfers by it, so it only has to be unique among those in flight;
// counting up from the current time keeps it unique across runs too.
func (c *Client) newID() int64 { return c.nextID.Add(1) }

func (c *Client) readLoop() {
	defer close(c.frames)
	defer c.r.reset()
	for {
		msg, err := c.t.Recv(context.Background())
		if err != nil {
			c.shutdown(err)
			return
		}
		f, err := decodeFrame(msg)
		if err != nil {
			c.log.Debug("dropping an unreadable message", "err", err, "len", len(msg))
			continue
		}
		if f.Type == TypeMultiPartMessage {
			whole, err := c.r.add(f.Payload)
			if err != nil {
				c.log.Debug("dropping a bad message part", "err", err)
				continue
			}
			if whole == nil {
				continue
			}
			if f, err = decodeFrame(whole); err != nil {
				c.log.Debug("dropping an unreadable reassembled message", "err", err)
				continue
			}
		}
		c.log.Debug("received", "message", f.String())
		select {
		case c.frames <- f:
		case <-c.done:
			return
		}
	}
}

// send encodes and transmits one message, splitting it if it is too large.
func (c *Client) send(ctx context.Context, msgType int32, m proto.Message) error {
	body, err := encodeFrame(msgType, m)
	if err != nil {
		return err
	}
	parts, err := split(body, c.newID())
	if err != nil {
		return err
	}
	c.log.Debug("sending", "message", typeName(msgType), "type", msgType, "bytes", len(body), "parts", len(parts))
	for _, part := range parts {
		if err := c.t.Send(ctx, part); err != nil {
			return fmt.Errorf("frameo: send %s: %w", typeName(msgType), err)
		}
	}
	return nil
}

// await waits for a message the predicate accepts. Anything else is logged and
// dropped: a frame volunteers status messages at any time, and none of them
// should derail an operation in progress.
//
// It waits only on the message queue, never on the connection's end directly,
// so a reply that arrived just before the connection dropped is still seen
// rather than lost to a race between the two.
func (c *Client) await(ctx context.Context, what string, accept func(Frame) bool) (Frame, error) {
	for {
		select {
		case f, ok := <-c.frames:
			if !ok {
				return Frame{}, fmt.Errorf("frameo: waiting for %s: %w", what, c.closedErr())
			}
			if accept(f) {
				return f, nil
			}
			c.log.Debug("ignoring an unrelated message while waiting", "for", what, "got", f.String())
		case <-ctx.Done():
			return Frame{}, fmt.Errorf("frameo: waiting for %s: %w", what, ctx.Err())
		}
	}
}

func expectType(t int32) func(Frame) bool {
	return func(f Frame) bool { return f.Type == t }
}

// GetInfo asks the frame to describe itself.
func (c *Client) GetInfo(ctx context.Context) (*pb.FrameInfo, error) {
	if err := c.send(ctx, TypeGetInfo, &pb.GetInfo{}); err != nil {
		return nil, err
	}
	f, err := c.await(ctx, "frame information", expectType(TypeFrameInfo))
	if err != nil {
		return nil, err
	}
	var info pb.FrameInfo
	if err := proto.Unmarshal(f.Payload, &info); err != nil {
		return nil, fmt.Errorf("frameo: malformed frame information: %w", err)
	}
	return &info, nil
}
