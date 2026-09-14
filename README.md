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

## What is left

Sending, listing, hiding and deleting have all been confirmed against a real
frame. Downloading has not: it was built from a decompile of the app rather
than by probing, so the message number and the shape of the reply are on paper
but not yet seen. `NEXT-STEPS.md` lists what remains, what each piece is
waiting on, and what to ask for.
