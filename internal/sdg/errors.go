// SPDX-License-Identifier: GPL-3.0-or-later

package sdg

import (
	"errors"
	"fmt"
)

var (
	// ErrRefused means the grid declined to connect us to the peer: the frame
	// is unknown, not paired with us, or refused the call.
	ErrRefused = errors.New("sdg: peer connection refused")
	// ErrPeerTimeout means the relay waited for the peer and gave up. The
	// usual cause is a frame that is powered off or off the network.
	ErrPeerTimeout = errors.New("sdg: peer did not answer")
	// ErrServerError is an internal error reported by the relay.
	ErrServerError = errors.New("sdg: relay server error")
	// ErrProtocol means the remote sent something this client cannot parse.
	ErrProtocol = errors.New("sdg: protocol error")
	// ErrDecrypt means a packet failed authentication. Either the keys are
	// wrong or the stream is corrupt.
	ErrDecrypt = errors.New("sdg: decryption failed")
	// ErrClosed is returned by operations on a connection that has shut down.
	ErrClosed = errors.New("sdg: connection closed")
	// ErrKeyMismatch means the device that answered presented a different
	// long-term key than the peer id we asked for.
	ErrKeyMismatch = errors.New("sdg: peer presented a different key")
	// ErrPairingFailed means the pairing challenge/response did not verify,
	// which in practice means the code was wrong.
	ErrPairingFailed = errors.New("sdg: pairing verification failed")
	// ErrBadOTP means the pairing code is not usable: too few or too many digits.
	ErrBadOTP = errors.New("sdg: malformed pairing code")
	// ErrMessageTooLarge means a message exceeds the negotiated maximum.
	ErrMessageTooLarge = errors.New("sdg: message too large")
)

// ForwardError is an unrecognised error code from the relay's forwarding stage.
type ForwardError struct{ Code uint32 }

func (e *ForwardError) Error() string {
	return fmt.Sprintf("sdg: relay forwarding error %d", e.Code)
}

// forwardError maps the relay's numeric codes onto this package's errors.
// Names and values come from the MSG_FORWARD_ERROR handling in opensdg.
func forwardError(code uint32) error {
	switch code {
	case 1: // FORWARD_SERVER_ERROR
		return ErrServerError
	case 2: // FORWARD_SYNTAX_ERROR
		return fmt.Errorf("%w: relay rejected our forwarding request as malformed", ErrProtocol)
	case 3: // FORWARD_BAD_TOKEN
		return fmt.Errorf("%w: relay rejected the tunnel id", ErrProtocol)
	case 4: // FORWARD_PEER_TIMEOUT
		return ErrPeerTimeout
	case 5: // FORWARD_BAD_VERSION
		return fmt.Errorf("%w: relay rejected our protocol version", ErrProtocol)
	default:
		return &ForwardError{Code: code}
	}
}
