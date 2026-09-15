# frameo

A standalone client that sends photos to a Frameo digital photo frame.

Frameo frames do not accept photos over any cloud API. Photos travel
peer-to-peer over Trifork's SecureDeviceGrid, an encrypted relay network, with
Frameo's own message protocol on top. This program implements both, so a frame
can be fed from a script or a server instead of from the phone app.

    frameo pair 12345678      # once, with the code the frame is showing
    frameo send photo.jpg     # thereafter, from anywhere

## Commands

    pair <code>          pair with the frame showing this code
    info                 describe the frame and how big its screen is
    send <file|url>...   send photos, from disk or from the web
    list                 list the photos on the frame
    get <id>... | all    copy photos off the frame into files
    hide <id>...         hide photos without removing them
    show <id>...         show photos that were hidden
    delete <id>...       remove photos from the frame
    discover             find frames on the local network
    frames               list the frames already paired
    forget <name>        forget a paired frame
    whoami               print this client's own identity
    raw <number>         send an empty message with that number, report replies
    help                 print the full usage, which says more than this does

Pairing is needed once per frame; the address is saved and works from anywhere
afterwards. `send` takes an http or https URL wherever it takes a path, and
fetches every photo before connecting to the frame, so a dead link costs
nothing. `get` writes `<date>_<time>_<id>.<extension>` in the current
directory, so a directory of them sorts into the order the photos were taken,
and keeps going past a photo it cannot fetch. `delete` is final; `hide` only
stops a photo being displayed.

## Options

    -frame <name>        which paired frame to use (default: the first paired)
    -net <how>           local, relay or auto (default auto)
    -discover <dur>      how long to look for the frame locally (default 2s)
    -caption <text>      caption to send with a photo
    -fit                 fit the whole photo on screen instead of cropping
    -out <path>          where get writes: a file for one photo, a directory
                         for many
    -size <which>        which stored copy get asks for (default full)
    -wait <dur>          how long get waits for one photo before asking again
                         (default 6s)
    -timeout <dur>       give up after this long, covering the whole run
                         (default 15m)
    -single-segment      send each photo as one message instead of a series
    -config <path>       configuration file (default: under the user config dir)
    -server <host:port>  use this grid server instead of Frameo's
    -v                   log the protocol exchange

A frame on the same network is reached directly, which skips the relay and is
several times faster; one elsewhere is reached through it. `-net local` and
`-net relay` force the choice, and a network that blocks multicast falls back
to the relay silently unless `-v` is given.

The frame does not scale a photo to order: it keeps the original and a preview
whose long side is 570 pixels, and `-size` only chooses between them -- though
a bare number is passed through as it stands, for a frame that draws the line
elsewhere. A preview is a twentieth of the bytes, which is what makes fetching
a whole library over the relay practical. Downloads are named after which copy
they are, so both can sit in one directory, and `get` prints the dimensions it
measured off the photo itself -- the frame states them nowhere.

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
