// SPDX-License-Identifier: GPL-3.0-or-later

package frameo

import (
	"fmt"
	"sync"

	"github.com/borje/unframeo/internal/frameo/pb"
	"google.golang.org/protobuf/proto"
)

// MaxMessage is the largest message the transport carries. Anything longer has
// to be split.
const MaxMessage = 16416

// chunkSize is how much of an oversized message travels in each part. The
// headroom below MaxMessage covers the wrapper the part is carried in.
const chunkSize = 16316

// split breaks an encoded message into transport-sized pieces. A message that
// already fits is returned unchanged, as a single piece.
//
// messageID ties the pieces together; the receiver reassembles by it. Parts of
// different messages may interleave, so it must be unique among messages still
// in flight.
func split(message []byte, messageID int64) ([][]byte, error) {
	if len(message) <= MaxMessage {
		return [][]byte{message}, nil
	}
	var parts [][]byte
	for i := 0; i*chunkSize < len(message); i++ {
		end := min((i+1)*chunkSize, len(message))
		part, err := encodeFrame(TypeMultiPartMessage, &pb.MultiPartMessage{
			MessageId:   int64(messageID),
			MessageSize: int32(len(message)),
			DataIndex:   int32(i),
			MessageData: message[i*chunkSize : end],
		})
		if err != nil {
			return nil, err
		}
		if len(part) > MaxMessage {
			return nil, fmt.Errorf("frameo: split produced a %d byte part, over the %d byte limit", len(part), MaxMessage)
		}
		parts = append(parts, part)
	}
	return parts, nil
}

// maxPartialMessages caps how many messages may be part-received at once. A
// peer that starts transfers and abandons them would otherwise grow this
// without limit.
const maxPartialMessages = 16

// reassembler rebuilds messages that arrived in pieces.
type reassembler struct {
	mu       sync.Mutex
	partial  map[int64]*partialMessage
	maxTotal int
}

type partialMessage struct {
	size int32
	// parts is indexed by position, because pieces may arrive out of order and
	// a piece may repeat.
	parts map[int32][]byte
	have  int
}

func newReassembler(maxTotal int) *reassembler {
	return &reassembler{partial: map[int64]*partialMessage{}, maxTotal: maxTotal}
}

// add takes one part and returns the complete message once every part has
// arrived, or nil while parts are still missing.
func (r *reassembler) add(payload []byte) ([]byte, error) {
	var part pb.MultiPartMessage
	if err := proto.Unmarshal(payload, &part); err != nil {
		return nil, fmt.Errorf("frameo: malformed message part: %w", err)
	}
	if part.GetMessageSize() <= 0 {
		return nil, fmt.Errorf("frameo: message part claims a total size of %d", part.GetMessageSize())
	}
	if r.maxTotal > 0 && int(part.GetMessageSize()) > r.maxTotal {
		return nil, fmt.Errorf("frameo: refusing a %d byte message, over the %d byte limit",
			part.GetMessageSize(), r.maxTotal)
	}
	if part.GetDataIndex() < 0 {
		return nil, fmt.Errorf("frameo: message part has a negative position")
	}
	// Widened deliberately: the position is chosen by the sender, and at 32
	// bits this product wraps to a negative number that would pass the bounds
	// check below.
	offset := int64(part.GetDataIndex()) * chunkSize
	if offset >= int64(part.GetMessageSize()) {
		return nil, fmt.Errorf("frameo: message part %d starts past the end of a %d byte message",
			part.GetDataIndex(), part.GetMessageSize())
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	p := r.partial[part.GetMessageId()]
	if p == nil {
		if len(r.partial) >= maxPartialMessages {
			return nil, fmt.Errorf("frameo: %d messages are already part-received; refusing to track more",
				len(r.partial))
		}
		p = &partialMessage{size: part.GetMessageSize(), parts: map[int32][]byte{}}
		r.partial[part.GetMessageId()] = p
	}
	if p.size != part.GetMessageSize() {
		return nil, fmt.Errorf("frameo: message %d changed size from %d to %d",
			part.GetMessageId(), p.size, part.GetMessageSize())
	}

	if _, seen := p.parts[part.GetDataIndex()]; !seen {
		p.parts[part.GetDataIndex()] = part.GetMessageData()
		p.have += len(part.GetMessageData())
	}
	if p.have < int(p.size) {
		return nil, nil
	}
	delete(r.partial, part.GetMessageId())

	out := make([]byte, 0, p.size)
	for i := int32(0); ; i++ {
		chunk, ok := p.parts[i]
		if !ok {
			break
		}
		out = append(out, chunk...)
	}
	if len(out) != int(p.size) {
		return nil, fmt.Errorf("frameo: reassembled %d bytes of a %d byte message", len(out), p.size)
	}
	return out, nil
}

// pending reports how many messages are partly received, for tests and logs.
func (r *reassembler) pending() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.partial)
}

// reset discards everything part-received, freeing it when the conversation
// ends.
func (r *reassembler) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	clear(r.partial)
}
