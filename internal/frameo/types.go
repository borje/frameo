// Package frameo speaks the message protocol a Frameo photo frame uses over a
// SecureDeviceGrid connection.
package frameo

import "errors"

// Every message is framed as two big-endian 32-bit integers followed by a
// protobuf: a constant, then the type that says which protobuf it is.
const (
	// framePrefix precedes every message. The frame reads it but dispatches
	// only on the type that follows.
	framePrefix = 18
	frameHeader = 8
)

// Message types. These are the values the frame dispatches on.
const (
	TypeGetInfo            = 1
	TypeFrameInfo          = 2
	TypeMedia              = 4
	TypeMediaDataSegment   = 5
	TypeAcknowledgeReceipt = 6
	TypePairingCode        = 8
	TypeReaction           = 10
	TypeEncryptedData      = 11
	TypeBackupStatus       = 19
	TypeRestoreStatus      = 22
	TypeMultiPartMessage   = 30
	TypeAllMediaMetaData   = 32
	TypeCalendarStatuses   = 40
)

// Message numbers this client needs but does not know. They were never
// observed: the numbers above come from the dispatch table in the app, and
// these three appear only at its send sites.
//
// Zero means unknown, and the commands that need them refuse rather than send
// a message a frame might read as something else entirely. Supply a candidate
// with the command line's -type option to try one against a real frame.
//
// There is a well-supported guess for the first. Every request whose answer is
// known is numbered one below that answer: GetInfo is 1 and FrameInfo is 2,
// and the same holds at 7/8, 18/19, 21/22, 42/43 and 47/48. AllMediaMetaData
// is 32, which puts GetAllMediaMetaData at 31. It is a request for a listing,
// so trying it costs nothing if the guess is wrong.
//
// The other two have no answering message to anchor them, and both change what
// is on the frame, so guessing is not worth the risk. Their numbers are in the
// app's own source, at the send sites in SDGController.
const (
	// CandidateGetAllMediaMetaData is the inferred number described above.
	CandidateGetAllMediaMetaData = 31

	TypeGetAllMediaMetaData   = 0
	TypeDeleteMedia           = 0
	TypeChangeMediaVisibility = 0
)

// ErrTypeUnknown means an operation needs a message number that has not been
// determined yet.
var ErrTypeUnknown = errors.New("frameo: this operation's message number is not known yet")

// typeName labels a message type for logs and errors.
func typeName(t int32) string {
	switch t {
	case TypeGetInfo:
		return "GetInfo"
	case TypeFrameInfo:
		return "FrameInfo"
	case TypeMedia:
		return "Media"
	case TypeMediaDataSegment:
		return "MediaDataSegment"
	case TypeAcknowledgeReceipt:
		return "AcknowledgeReceipt"
	case TypePairingCode:
		return "PairingCode"
	case TypeReaction:
		return "Reaction"
	case TypeEncryptedData:
		return "EncryptedData"
	case TypeBackupStatus:
		return "BackupStatus"
	case TypeRestoreStatus:
		return "RestoreStatus"
	case TypeMultiPartMessage:
		return "MultiPartMessage"
	case TypeAllMediaMetaData:
		return "AllMediaMetaData"
	case TypeCalendarStatuses:
		return "CalendarStatuses"
	default:
		return "unknown"
	}
}
