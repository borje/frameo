// Package frameotest provides a stand-in Frameo frame, so the client can be
// tested end to end without a device.
//
// It implements the frame's side of the protocol from the protocol
// description rather than by reusing the client's code, so a mistake shared by
// both sides cannot pass unnoticed.
package frameotest

import (
	"encoding/binary"
	"fmt"
	"sync"

	"frameo/internal/frameo/pb"
	"google.golang.org/protobuf/proto"
)

// MessageRW is a message pipe to the client. A test tunnel satisfies it.
type MessageRW interface {
	Send([]byte) error
	Recv() ([]byte, error)
}

// Photo is a completed transfer.
type Photo struct {
	Media *pb.Media
	Data  []byte
}

// Frame is a fake photo frame.
type Frame struct {
	// Info is what the frame reports when asked to describe itself.
	Info *pb.FrameInfo
	// RefuseTransfers makes the frame report an error instead of accepting a
	// photo, so the failure path can be tested.
	RefuseTransfers bool
	// DropAck makes the frame accept a photo but never confirm it.
	DropAck bool
	// ListType is the message number this frame answers a listing request on.
	// Configurable rather than fixed to frameo.TypeGetAllMediaMetaData so this
	// package stays independent of that client-side constant.
	ListType int32
	// DeleteType is the message number this frame accepts deletions on.
	DeleteType int32
	// VisibilityType is the message number this frame accepts visibility
	// changes on. Configurable for the same reason as ListType.
	VisibilityType int32
	// Library is what a listing reports.
	Library []*pb.MediaMetaData

	mu       sync.Mutex
	deleted  []int64
	photos   []Photo
	partial  map[int64]*transfer
	multi    map[int64]*multipart
	unknown  []int32
	segments int
}

type transfer struct {
	media *pb.Media
	data  []byte
}

type multipart struct {
	size  int32
	parts map[int32][]byte
	have  int
}

// New creates a frame with plausible defaults.
func New() *Frame {
	return &Frame{
		Info: &pb.FrameInfo{
			Name:                      "Test Frame",
			Placement:                 "Living room",
			ScreenWidth:               1280,
			ScreenHeight:              800,
			HasPermissionViewPhotos:   true,
			HasPermissionManagePhotos: true,
		},
		partial: map[int64]*transfer{},
		multi:   map[int64]*multipart{},
	}
}

// Photos returns the transfers that completed.
func (f *Frame) Photos() []Photo {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Photo(nil), f.photos...)
}

// Deleted returns the ids the frame was asked to remove.
func (f *Frame) Deleted() []int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int64(nil), f.deleted...)
}

// Segments reports how many data segments arrived, which distinguishes a
// segmented transfer from a single-message one.
func (f *Frame) Segments() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.segments
}

// UnknownTypes lists message numbers the frame did not recognise.
func (f *Frame) UnknownTypes() []int32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int32(nil), f.unknown...)
}

// Serve runs the frame until the connection ends.
func (f *Frame) Serve(rw MessageRW) error {
	for {
		msg, err := rw.Recv()
		if err != nil {
			return nil
		}
		if err := f.handle(rw, msg); err != nil {
			return err
		}
	}
}

func (f *Frame) handle(rw MessageRW, msg []byte) error {
	msgType, payload, err := decode(msg)
	if err != nil {
		return err
	}

	if msgType == 30 {
		whole, err := f.reassemble(payload)
		if err != nil || whole == nil {
			return err
		}
		if msgType, payload, err = decode(whole); err != nil {
			return err
		}
	}

	if f.ListType != 0 && msgType == f.ListType {
		f.mu.Lock()
		items := append([]*pb.MediaMetaData(nil), f.Library...)
		f.mu.Unlock()
		return send(rw, 32, &pb.AllMediaMetaData{MediaMetaDataItems: items})
	}
	if f.DeleteType != 0 && msgType == f.DeleteType {
		var req pb.DeleteMedia
		if err := proto.Unmarshal(payload, &req); err != nil {
			return fmt.Errorf("frameotest: malformed deletion request: %w", err)
		}
		f.mu.Lock()
		f.deleted = append(f.deleted, req.GetMediaIds()...)
		f.mu.Unlock()
		if id := req.GetRequiresAcknowledgeReceiptId(); id != 0 {
			return send(rw, 6, &pb.AcknowledgeReceipt{AcknowledgeId: id})
		}
		return nil
	}

	if f.VisibilityType != 0 && msgType == f.VisibilityType {
		var req pb.ChangeMediaVisibility
		if err := proto.Unmarshal(payload, &req); err != nil {
			return fmt.Errorf("frameotest: malformed visibility request: %w", err)
		}
		// A real frame keeps a hidden photo and reports it as hidden in the
		// listing, so the change is applied to the library rather than
		// recorded separately.
		f.mu.Lock()
		for _, id := range req.GetMediaIds() {
			for _, m := range f.Library {
				if m.GetMediaId() == id {
					m.IsVisible = req.GetIsVisible()
				}
			}
		}
		f.mu.Unlock()
		if id := req.GetRequiresAcknowledgeReceiptId(); id != 0 {
			return send(rw, 6, &pb.AcknowledgeReceipt{AcknowledgeId: id})
		}
		return nil
	}

	switch msgType {
	case 1: // GetInfo
		return send(rw, 2, f.Info)

	case 4: // Media
		var media pb.Media
		if err := proto.Unmarshal(payload, &media); err != nil {
			return fmt.Errorf("frameotest: malformed media header: %w", err)
		}
		f.mu.Lock()
		f.partial[media.GetId()] = &transfer{media: &media}
		f.mu.Unlock()
		return nil

	case 5: // MediaDataSegment
		var seg pb.MediaDataSegment
		if err := proto.Unmarshal(payload, &seg); err != nil {
			return fmt.Errorf("frameotest: malformed media segment: %w", err)
		}
		return f.appendSegment(rw, &seg)

	default:
		f.mu.Lock()
		f.unknown = append(f.unknown, msgType)
		f.mu.Unlock()
		return nil
	}
}

// appendSegment appends file data to whichever transfer is open. The real
// frame has no per-segment addressing either: it appends to the transfer it is
// currently receiving, which is why segments must arrive in order.
func (f *Frame) appendSegment(rw MessageRW, seg *pb.MediaDataSegment) error {
	f.mu.Lock()
	f.segments++
	var t *transfer
	var id int64
	for k, v := range f.partial {
		t, id = v, k
		break
	}
	if t == nil {
		f.mu.Unlock()
		return fmt.Errorf("frameotest: file data arrived with no transfer open")
	}
	t.data = append(t.data, seg.GetData()...)
	done := len(t.data) >= int(t.media.GetSize())
	if done {
		delete(f.partial, id)
		if len(t.data) == int(t.media.GetSize()) && !f.RefuseTransfers {
			f.photos = append(f.photos, Photo{Media: t.media, Data: t.data})
		}
	}
	size := t.media.GetSize()
	got := len(t.data)
	f.mu.Unlock()

	ackID := seg.GetRequiresAcknowledgeReceiptId()
	if ackID == 0 {
		return nil
	}
	if !done {
		return fmt.Errorf("frameotest: transfer was acknowledged after %d of %d bytes", got, size)
	}
	if f.DropAck {
		return nil
	}
	ack := &pb.AcknowledgeReceipt{AcknowledgeId: ackID}
	if f.RefuseTransfers {
		ack.Error = &pb.Error{Code: pb.Error_Code(7)} // failed to receive the item
	}
	return send(rw, 6, ack)
}

func (f *Frame) reassemble(payload []byte) ([]byte, error) {
	var part pb.MultiPartMessage
	if err := proto.Unmarshal(payload, &part); err != nil {
		return nil, fmt.Errorf("frameotest: malformed message part: %w", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	m := f.multi[part.GetMessageId()]
	if m == nil {
		m = &multipart{size: part.GetMessageSize(), parts: map[int32][]byte{}}
		f.multi[part.GetMessageId()] = m
	}
	if _, seen := m.parts[part.GetDataIndex()]; !seen {
		m.parts[part.GetDataIndex()] = part.GetMessageData()
		m.have += len(part.GetMessageData())
	}
	if m.have < int(m.size) {
		return nil, nil
	}
	delete(f.multi, part.GetMessageId())

	out := make([]byte, 0, m.size)
	for i := int32(0); ; i++ {
		chunk, ok := m.parts[i]
		if !ok {
			break
		}
		out = append(out, chunk...)
	}
	if len(out) != int(m.size) {
		return nil, fmt.Errorf("frameotest: reassembled %d bytes of a %d byte message", len(out), m.size)
	}
	return out, nil
}

func decode(msg []byte) (int32, []byte, error) {
	if len(msg) < 8 {
		return 0, nil, fmt.Errorf("frameotest: message of %d bytes is too short", len(msg))
	}
	if prefix := binary.BigEndian.Uint32(msg[0:4]); prefix != 18 {
		return 0, nil, fmt.Errorf("frameotest: message prefix is %d, want 18", prefix)
	}
	return int32(binary.BigEndian.Uint32(msg[4:8])), msg[8:], nil
}

func send(rw MessageRW, msgType int32, m proto.Message) error {
	payload, err := proto.Marshal(m)
	if err != nil {
		return err
	}
	buf := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(buf[0:4], 18)
	binary.BigEndian.PutUint32(buf[4:8], uint32(msgType))
	copy(buf[8:], payload)
	return rw.Send(buf)
}
