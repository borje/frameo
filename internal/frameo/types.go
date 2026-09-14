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

// Message numbers this client needs but does not know. GetAllMediaMetaData,
// DeleteMedia and ChangeMediaVisibility are defined in the app's protobuf
// schema and the app has receive-side dispatch cases for their replies (32,
// and for the related AllMediaIds/AllMediaIdsSegment pair, 25/26), but the app
// itself has no send site for any of the three requests anywhere in its code
// (checked against a decompile of v1.40.5). The phone never asks for these;
// whatever sends them lives in the frame's firmware, which is not available to
// inspect. So there is no source to read the numbers from, guessed or
// otherwise.
//
// Zero means unknown, and the commands that need them refuse rather than send
// a message a frame might read as something else entirely. Supply a candidate
// with the command line's -type option to try one against a real frame.
//
// CandidateGetAllMediaMetaData is a guess, not a recovered value: requests are
// often numbered one below their answer elsewhere in this protocol (GetInfo/
// FrameInfo at 1/2, and the same gap at 7/8, 18/19, 21/22, 42/43, 47/48), and
// AllMediaMetaData's reply is 32, so 31 is the first thing worth trying. It is
// read-only, so trying it costs nothing if wrong. 24 is a second candidate
// worth trying, by the same one-below pattern applied to AllMediaIds (25)
// instead. Confirming either still needs a real frame.
//
// DeleteMedia and ChangeMediaVisibility have no answering message to anchor a
// guess at all, and both change what is on the frame, so this client does not
// guess them. Finding them needs either a live capture of a real remote-manage
// session, or a live probe with `frameo raw <n>` against a real frame, judging
// success by whether the frame answers or by inspecting its state afterward.
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
