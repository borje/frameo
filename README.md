# frameo

A standalone client that sends photos to a Frameo digital photo frame.

Frameo frames do not accept photos over any cloud API. Photos travel
peer-to-peer over Trifork's SecureDeviceGrid, an encrypted relay network, with
Frameo's own message protocol on top. This program implements both, so a frame
can be fed from a script or a server instead of from the phone app.

    frameo pair 12345678      # once, with the code the frame is showing
    frameo info               # what the frame is and how big its screen is
    frameo send photo.jpg     # send a photo, named by path or by URL
    frameo list               # what is on the frame
    frameo get 12345          # copy one back off the frame
    frameo delete 12345       # remove one
    frameo discover           # frames on this network

A frame on the same network is reached directly, which skips the relay and is
several times faster; one elsewhere is reached through it. `-net local` and
`-net relay` force the choice.

## Layout

- `internal/sdg` speaks SecureDeviceGrid: identity keys, the grid connection,
  pairing, and peer connections both relayed and direct. It is a pure-Go port
  of the [opensdg](https://github.com/Sonic-Amiga/opensdg) C library, verified
  against that implementation's own output byte for byte; the direct local
  connection is not in opensdg and was worked out against a real frame, as
  `LOCAL_DIRECT.md` describes.
- `internal/mdns` finds frames on the local network, by browsing for the
  DNS-SD service they advertise.
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

## What is left

Sending, listing, downloading, hiding, deleting and the direct local
connection have all been confirmed against a real frame. What is left is
mostly what this client does not say for itself — it sends no thumbnail and
does not identify itself to the frame — along with videos, greeting cards and
resuming an interrupted transfer. `NEXT-STEPS.md` lists what remains, what each
piece is waiting on, and what to ask for.
