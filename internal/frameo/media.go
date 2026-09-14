package frameo

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"frameo/internal/frameo/pb"
	"google.golang.org/protobuf/proto"
)

// Photo describes one photo to send.
type Photo struct {
	// Path is the file to read.
	Path string
	// Caption is shown with the photo on the frame. Optional.
	Caption string
	// Taken is the capture date the frame files the photo under. Zero means
	// the file's modification time.
	Taken time.Time
	// Fit selects scaling: false crops to fill the screen around the centre
	// point, true fits the whole photo inside it.
	Fit bool
	// CenterX and CenterY place the crop focus, from 0 to 1. Zero values mean
	// the centre of the photo.
	CenterX, CenterY float32
	// SingleSegment sends the file as one message and lets the transport split
	// it, instead of sending a series of segments. The app sends segments; this
	// exists to try the other shape against a frame that rejects them.
	SingleSegment bool
}

// SendPhoto transfers one photo and waits for the frame to confirm it.
//
// The frame is told the total size up front and then appends whatever arrives
// until it has that many bytes, so the data must be sent in order and nothing
// else may be interleaved into the same transfer.
func (c *Client) SendPhoto(ctx context.Context, p Photo) (int64, error) {
	data, err := os.ReadFile(p.Path)
	if err != nil {
		return 0, fmt.Errorf("frameo: %w", err)
	}
	if len(data) == 0 {
		return 0, fmt.Errorf("frameo: %s is empty", p.Path)
	}
	// The frame is told the size in a 32-bit field and waits for exactly that
	// many bytes, so a file it cannot describe must be refused here rather
	// than announced as a smaller one.
	if len(data) > math.MaxInt32 {
		return 0, fmt.Errorf("frameo: %s is %d bytes, larger than the protocol can describe", p.Path, len(data))
	}

	taken := p.Taken
	if taken.IsZero() {
		if st, err := os.Stat(p.Path); err == nil {
			taken = st.ModTime()
		} else {
			taken = time.Now()
		}
	}
	cx, cy := p.CenterX, p.CenterY
	if cx == 0 {
		cx = 0.5
	}
	if cy == 0 {
		cy = 0.5
	}
	scale := pb.Media_CENTER_POINT_CROP
	if p.Fit {
		scale = pb.Media_FIT_INSIDE
	}

	id := c.newID()
	media := &pb.Media{
		Id:            id,
		ContentId:     id,
		Size:          int32(len(data)),
		FileExtension: fileExtension(p.Path),
		Type:          pb.Media_PICTURE,
		ScaleType:     scale,
		CenterPointX:  cx,
		CenterPointY:  cy,
		CaptureDate:   taken.UnixMilli(),
		Caption:       p.Caption,
	}
	if err := c.send(ctx, TypeMedia, media); err != nil {
		return 0, err
	}

	ackID := c.newID()
	segments := segmentCount(len(data), p.SingleSegment)
	c.log.Debug("sending photo", "path", p.Path, "bytes", len(data), "id", id, "segments", segments)

	for i, chunk := range chunks(data, p.SingleSegment) {
		seg := &pb.MediaDataSegment{Data: chunk}
		if i == segments-1 {
			seg.RequiresAcknowledgeReceiptId = ackID
		}
		if err := c.send(ctx, TypeMediaDataSegment, seg); err != nil {
			return 0, err
		}
	}

	if err := c.awaitAck(ctx, ackID, "the photo to be accepted"); err != nil {
		return 0, err
	}
	return id, nil
}

// awaitAck waits for the frame to confirm the operation with the given id. A
// confirmation can carry a failure, so the answer is examined rather than
// merely counted.
func (c *Client) awaitAck(ctx context.Context, ackID int64, what string) error {
	ctx, cancel := context.WithTimeout(ctx, AckTimeout)
	defer cancel()

	f, err := c.await(ctx, what, func(f Frame) bool {
		if f.Type != TypeAcknowledgeReceipt {
			return false
		}
		var ack pb.AcknowledgeReceipt
		if err := proto.Unmarshal(f.Payload, &ack); err != nil {
			return false
		}
		return ack.GetAcknowledgeId() == ackID
	})
	if err != nil {
		return err
	}
	var ack pb.AcknowledgeReceipt
	if err := proto.Unmarshal(f.Payload, &ack); err != nil {
		return fmt.Errorf("frameo: malformed confirmation: %w", err)
	}
	if e := ack.GetError(); e != nil && e.GetCode() != 0 {
		return fmt.Errorf("frameo: the frame rejected %s: error code %d", what, e.GetCode())
	}
	return nil
}

// chunks yields the pieces the file is sent in.
func chunks(data []byte, single bool) [][]byte {
	if single {
		return [][]byte{data}
	}
	var out [][]byte
	for off := 0; off < len(data); off += segmentSize {
		out = append(out, data[off:min(off+segmentSize, len(data))])
	}
	return out
}

func segmentCount(n int, single bool) int {
	if single {
		return 1
	}
	return (n + segmentSize - 1) / segmentSize
}

// fileExtension returns the extension the frame should store the file under,
// lowercase and without a dot.
func fileExtension(path string) string {
	ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(path)), ".")
	if ext == "" {
		return "jpg"
	}
	if ext == "jpeg" {
		return "jpg"
	}
	return ext
}

// ListMedia asks the frame what it is holding. msgType overrides the message
// number when it is non-zero, which is how a candidate is tried while the real
// one is unknown.
func (c *Client) ListMedia(ctx context.Context, msgType int32) ([]*pb.MediaMetaData, error) {
	if msgType == 0 {
		msgType = TypeGetAllMediaMetaData
	}
	if msgType == 0 {
		return nil, fmt.Errorf("listing media: %w", ErrTypeUnknown)
	}
	if err := c.send(ctx, msgType, &pb.GetAllMediaMetaData{}); err != nil {
		return nil, err
	}
	f, err := c.await(ctx, "the media list", expectType(TypeAllMediaMetaData))
	if err != nil {
		return nil, err
	}
	var list pb.AllMediaMetaData
	if err := proto.Unmarshal(f.Payload, &list); err != nil {
		return nil, fmt.Errorf("frameo: malformed media list: %w", err)
	}
	if e := list.GetError(); e != nil && e.GetCode() != 0 {
		return nil, fmt.Errorf("frameo: the frame refused to list media, error code %d", e.GetCode())
	}
	return list.GetMediaMetaDataItems(), nil
}

// DeleteMedia removes photos from the frame and waits for confirmation.
// msgType overrides the message number when it is non-zero.
func (c *Client) DeleteMedia(ctx context.Context, ids []int64, msgType int32) error {
	if len(ids) == 0 {
		return nil
	}
	if msgType == 0 {
		msgType = TypeDeleteMedia
	}
	if msgType == 0 {
		return fmt.Errorf("deleting media: %w", ErrTypeUnknown)
	}
	ackID := c.newID()
	req := &pb.DeleteMedia{MediaIds: ids, RequiresAcknowledgeReceiptId: ackID}
	if err := c.send(ctx, msgType, req); err != nil {
		return err
	}
	return c.awaitAck(ctx, ackID, "the deletion to be confirmed")
}

// SetMediaVisible shows or hides photos on the frame without deleting them.
func (c *Client) SetMediaVisible(ctx context.Context, ids []int64, visible bool, msgType int32) error {
	if len(ids) == 0 {
		return nil
	}
	if msgType == 0 {
		msgType = TypeChangeMediaVisibility
	}
	if msgType == 0 {
		return fmt.Errorf("changing visibility: %w", ErrTypeUnknown)
	}
	ackID := c.newID()
	req := &pb.ChangeMediaVisibility{MediaIds: ids, IsVisible: visible, RequiresAcknowledgeReceiptId: ackID}
	if err := c.send(ctx, msgType, req); err != nil {
		return err
	}
	return c.awaitAck(ctx, ackID, "the visibility change to be confirmed")
}

// SendRaw sends an arbitrary message and is the tool for identifying the
// message numbers that are still unknown. Everything the frame says in reply
// arrives through Frames.
func (c *Client) SendRaw(ctx context.Context, msgType int32, payload []byte) error {
	body := encodeFrameBytes(msgType, payload)
	parts, err := split(body, c.newID())
	if err != nil {
		return err
	}
	for _, part := range parts {
		if err := c.t.Send(ctx, part); err != nil {
			return err
		}
	}
	return nil
}

// Frames exposes messages the frame sends. It is used by the raw command and
// must not be read from while another operation is in progress, since both
// take from the same queue.
func (c *Client) Frames() <-chan Frame { return c.frames }
