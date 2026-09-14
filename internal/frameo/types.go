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

// Message types this client sends but whose numbers are not yet known. They
// were recovered from the frame's receive dispatch, which only covers what the
// frame accepts; these three travel the other way and their numbers live at
// the app's send sites.
//
// Until they are filled in, the commands that need them refuse rather than
// send a message the frame would misread. The "raw" command exists to probe
// candidates against a real frame.
const (
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
