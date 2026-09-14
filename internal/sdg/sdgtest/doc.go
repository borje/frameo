// Package sdgtest runs the server half of the SecureDeviceGrid protocol in
// process, so the client can be exercised end to end without touching the
// network or a real device.
//
// It deliberately reimplements the server side from the protocol description
// rather than sharing code with the client: a shared helper that is wrong in
// both directions would let a broken client pass.
package sdgtest
