# frameo

A standalone client that sends photos to a Frameo digital photo frame.

Frameo frames do not accept photos over any cloud API. Photos travel
peer-to-peer over Trifork's SecureDeviceGrid, an encrypted relay network, with
Frameo's own message protocol on top. This program implements both, so a frame
can be fed from a script or a server instead of from the phone app.

    frameo pair 12345678      # once, with the code the frame is showing
    frameo info               # what the frame is and how big its screen is
    frameo send photo.jpg     # send a photo
    frameo list               # what is on the frame
    frameo delete 12345       # remove one

## Layout

- `internal/sdg` speaks SecureDeviceGrid: identity keys, the grid connection,
  pairing, and relayed peer connections. It is a pure-Go port of the
  [opensdg](https://github.com/Sonic-Amiga/opensdg) C library, verified against
  that implementation's own output byte for byte.
- `internal/frameo` speaks the Frameo message protocol that rides on top.
- `cmd/frameo` is the command line.

## Status and provenance

The protocol description this is built from was recovered by reverse
engineering the Frameo Android app. SecureDeviceGrid and the Frameo protocol
are both proprietary; opensdg, which served as the specification for the
transport, is GPLv3 and restricted to non-commercial use. This is a
personal-use interoperability project.

## Building

    go build ./cmd/frameo

Regenerating the protobuf bindings additionally needs `protoc` and
`protoc-gen-go`, but the generated files are checked in, so an ordinary build
does not.

## Finishing the job

Two things still need a real frame.

**Pairing and sending have never run against one.** Everything up to the
pairing exchange has: the client reaches Frameo's grid, completes the tunnel
handshake, and gets a proper refusal when it asks to pair with a code that does
not exist. The rest is exercised against a stand-in frame. To try the real
thing:

    frameo pair <the code on the frame>
    frameo info
    frameo send photo.jpg
    go test -tags live ./internal/frameo -v          # more thorough, same path

Add `-v` to any command to see the protocol exchange.

**Listing and deleting need message numbers nobody has seen.** Every other
number was recovered from the app's dispatch table, which covers only what the
app receives. These two travel the other way. Both commands refuse rather than
send a message a frame might read as something else.

For listing there is a good guess. Requests are numbered one below their
answers throughout the protocol, and the answer to a listing is 32, so try:

    frameo -type 31 list

Deleting has no answering message to anchor it, and it changes what is on the
frame, so it is better read out of the app than guessed at. The numbers are at
the send sites in the app's own `SDGController`.
