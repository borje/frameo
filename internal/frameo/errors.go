package frameo

import (
	"fmt"

	"frameo/internal/frameo/pb"
)

// FrameError is a refusal the frame itself reported, as distinct from a failure
// of the connection or of this client. Most replies carry an Error field, and
// the codes mean the same thing whichever reply they arrive in.
//
// It is worth distinguishing because it is a settled answer: the frame
// understood the request and declined it, so asking again will not help.
type FrameError struct {
	// What names the operation that was refused, for the message.
	What string
	Code pb.Error_Code
}

func (e *FrameError) Error() string {
	return fmt.Sprintf("frameo: the frame refused %s: %s", e.What, errorText(e.Code))
}

// errorText puts words to the frame's numeric codes. The set was recovered from
// a decompile of the app; a code outside it is reported as a number rather than
// guessed at.
func errorText(code pb.Error_Code) string {
	switch code {
	case pb.Error_UNAUTHORIZED:
		return "this client is not authorised"
	case pb.Error_SERVER_ERROR:
		return "the frame reported an error of its own"
	case pb.Error_BAD_REQUEST:
		return "the frame did not understand the request"
	case pb.Error_GENERIC_FAILURE:
		return "the frame reported a failure without saying what"
	case pb.Error_MISSING_PERMISSION:
		return "this pairing may not do that; approve the client on the frame itself"
	case pb.Error_MISSING_MEDIA_ITEM:
		return "the frame has no photo with that id"
	case pb.Error_FAILED_SENDING_MEDIA_ITEM:
		return "the frame could not send the photo"
	case pb.Error_NOT_FOUND:
		return "not found"
	case pb.Error_DECLINED:
		return "the frame declined"
	default:
		return fmt.Sprintf("error code %d", int32(code))
	}
}

// frameError turns a reply's Error field into a Go error, or nil when the reply
// reports success. A missing Error counts as success: proto3 omits zero values,
// so a reply that went well usually carries no Error at all.
func frameError(what string, e *pb.Error) error {
	if e == nil || e.GetCode() == pb.Error_NONE {
		return nil
	}
	return &FrameError{What: what, Code: e.GetCode()}
}
