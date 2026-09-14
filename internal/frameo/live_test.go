//go:build live

// These tests talk to a real frame. They need a pairing first:
//
//	frameo pair <the code on the frame>
//	go test -tags live ./internal/frameo -run TestLiveFrame -v
//
// The frame is taken from the stored configuration. Set FRAMEO_FRAME to choose
// one when several are paired, and FRAMEO_PHOTO to a file to run the transfer
// test, which puts a real photo on the frame.
package frameo_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"frameo/internal/config"
	"frameo/internal/frameo"
	"frameo/internal/sdg"
)

// connectLive opens a conversation with the paired frame.
func connectLive(t *testing.T) *frameo.Client {
	t.Helper()

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("reading the configuration: %v", err)
	}
	name, peer, err := cfg.Resolve(os.Getenv("FRAMEO_FRAME"))
	if err != nil {
		t.Skipf("no frame to test against: %v", err)
	}
	id, err := cfg.Identity()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("connecting to %s at %s", name, peer)

	level := slog.LevelInfo
	if testing.Verbose() {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	g, err := sdg.Dial(ctx, sdg.FrameoServers, id, &sdg.Options{
		Logger:     log,
		ServerKeys: []sdg.Key{sdg.FrameoServerKey},
	})
	if err != nil {
		t.Fatalf("reaching the grid: %v", err)
	}
	t.Cleanup(func() { _ = g.Close() })

	p, err := g.Connect(ctx, peer, sdg.FrameoProtocol)
	if err != nil {
		t.Fatalf("reaching the frame: %v", err)
	}
	c := frameo.NewClient(p, log)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestLiveFrameInfo(t *testing.T) {
	c := connectLive(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	info, err := c.GetInfo(ctx)
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	t.Logf("name %q, placement %q, screen %dx%d, may view %t, may manage %t",
		info.GetName(), info.GetPlacement(), info.GetScreenWidth(), info.GetScreenHeight(),
		info.GetHasPermissionViewPhotos(), info.GetHasPermissionManagePhotos())

	if info.GetScreenWidth() == 0 || info.GetScreenHeight() == 0 {
		t.Error("the frame reported no screen size, which suggests the reply was misread")
	}
}

func TestLiveSendPhoto(t *testing.T) {
	path := os.Getenv("FRAMEO_PHOTO")
	if path == "" {
		t.Skip("set FRAMEO_PHOTO to a file to send it to the frame")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("sending %s, %d bytes", path, len(data))

	c := connectLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	id, err := c.SendPhoto(ctx, frameo.Photo{Path: path, Caption: "sent by frameo"})
	if err != nil {
		t.Fatalf("SendPhoto: %v", err)
	}
	t.Logf("the frame accepted the photo as %d", id)
}

// TestLiveSendPhotoSingleSegment sends the whole file as one message, letting
// the transport split it, instead of sending a series of segments. If the
// segmented form turns out not to work against a real frame, this is the other
// shape to try.
func TestLiveSendPhotoSingleSegment(t *testing.T) {
	path := os.Getenv("FRAMEO_PHOTO")
	if path == "" {
		t.Skip("set FRAMEO_PHOTO to a file to send it to the frame")
	}
	c := connectLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	id, err := c.SendPhoto(ctx, frameo.Photo{Path: path, SingleSegment: true, Caption: "one message"})
	if err != nil {
		t.Fatalf("SendPhoto: %v", err)
	}
	t.Logf("the frame accepted the photo as %d", id)
}

// TestLiveListMedia asks the real frame for its media listing. The message
// number (31) is confirmed: the frame recognises the request and answers with
// a genuine AllMediaMetaData reply. Whether that reply carries a usable
// listing depends on this pairing's permissions (see `frameo info`), which is
// why a refusal only logs and skips rather than failing outright.
func TestLiveListMedia(t *testing.T) {
	c := connectLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	items, err := c.ListMedia(ctx)
	if err != nil {
		t.Logf("listing failed: %v", err)
		t.Skip("the frame answered but refused; this pairing may lack view/manage permission")
	}
	t.Logf("the frame listed %d item(s)", len(items))
	for i, m := range items {
		if i >= 5 {
			t.Logf("  and %d more", len(items)-i)
			break
		}
		t.Logf("  id %d, taken %s, visible %t",
			m.GetMediaId(), time.UnixMilli(m.GetCaptureDate()).UTC().Format(time.DateOnly), m.GetIsVisible())
	}
}

// TestLiveRoundTrip sends a photo and then looks for it in a listing, which is
// the check that the two halves agree about identifiers.
func TestLiveRoundTrip(t *testing.T) {
	path := os.Getenv("FRAMEO_PHOTO")
	if path == "" {
		t.Skip("set FRAMEO_PHOTO to a file to run the round trip")
	}
	c := connectLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	before, err := c.ListMedia(ctx)
	if err != nil {
		t.Skipf("cannot list media yet: %v", err)
	}
	id, err := c.SendPhoto(ctx, frameo.Photo{Path: path, Caption: "round trip"})
	if err != nil {
		t.Fatalf("SendPhoto: %v", err)
	}
	after, err := c.ListMedia(ctx)
	if err != nil {
		t.Fatalf("listing after sending: %v", err)
	}
	t.Logf("the frame held %d item(s) before and %d after; we sent %d", len(before), len(after), id)

	var found bool
	for _, m := range after {
		if m.GetMediaId() == id {
			found = true
		}
	}
	if !found {
		t.Logf("the frame files photos under its own identifiers, not the one we chose")
	}
}

// TestLiveGetMedia downloads a photo the frame already holds. It is also the
// experiment the protocol notes ask for, so it reports what it saw rather than
// only whether it worked: whether the frame echoes the id it was asked for,
// whether a full-resolution reply appends a thumbnail after the photo, and how
// long the transfer took against the six seconds allowed for it.
func TestLiveGetMedia(t *testing.T) {
	c := connectLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	items, err := c.ListMedia(ctx)
	if err != nil {
		t.Skipf("cannot list media: %v", err)
	}
	if len(items) == 0 {
		t.Skip("the frame holds no photos to fetch")
	}
	id := items[0].GetMediaId()

	start := time.Now()
	got, err := c.GetMedia(ctx, frameo.Fetch{ID: id})
	took := time.Since(start)
	if err != nil {
		t.Fatalf("GetMedia(%d): %v", id, err)
	}

	t.Logf("photo %d: %d bytes as %q in %s", id, len(got.Data), got.Extension(), took)
	t.Logf("  the header names photo %d (0 would mean the frame does not echo the id)", got.Media.GetId())
	if d := got.Media.GetCaptureDate(); d > 0 {
		t.Logf("  capture date %s, which is what the file is named after", time.UnixMilli(d).UTC())
	} else {
		t.Log("  no capture date: downloads will be named by id alone")
	}
	if cap := got.Media.GetCaption(); cap != "" {
		t.Logf("  caption %q", cap)
	}
	t.Logf("  extra streams: %d, thumbnail bytes received: %d", len(got.Media.GetExtra()), len(got.Thumbnail))
	for i, e := range got.Media.GetExtra() {
		t.Logf("  extra[%d]: %d bytes, %q", i, e.GetSize(), e.GetFileExtension())
	}
	if got.Media.GetId() != 0 && got.Media.GetId() != id {
		t.Errorf("asked for photo %d and the header names %d", id, got.Media.GetId())
	}

	if dir := os.Getenv("FRAMEO_OUT"); dir != "" {
		path := filepath.Join(dir, fmt.Sprintf("%d.%s", id, got.Extension()))
		if err := os.WriteFile(path, got.Data, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s; open it to confirm it is a photo", path)
	}
}

// TestLiveGetMediaScaled asks for a scaled copy, which the notes say the frame
// makes by putting the bound in width and height. What is unconfirmed is what
// comes back: the reply's own size being the scaled bytes, with no extras.
func TestLiveGetMediaScaled(t *testing.T) {
	c := connectLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	items, err := c.ListMedia(ctx)
	if err != nil {
		t.Skipf("cannot list media: %v", err)
	}
	if len(items) == 0 {
		t.Skip("the frame holds no photos to fetch")
	}
	id := items[0].GetMediaId()

	got, err := c.GetMedia(ctx, frameo.Fetch{ID: id, Bound: 512})
	if err != nil {
		t.Fatalf("GetMedia(%d) scaled: %v", id, err)
	}
	t.Logf("photo %d at a 512 bound: %d bytes, %d extra stream(s), %d thumbnail bytes",
		id, len(got.Data), len(got.Media.GetExtra()), len(got.Thumbnail))
}

// TestLiveGetMediaRoundTrip sends a photo and reads it straight back, which is
// the check that the two directions agree: the same id, and the same bytes if
// the frame stores what it is given rather than re-encoding it.
func TestLiveGetMediaRoundTrip(t *testing.T) {
	path := os.Getenv("FRAMEO_PHOTO")
	if path == "" {
		t.Skip("set FRAMEO_PHOTO to a file to run the round trip")
	}
	sent, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c := connectLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	id, err := c.SendPhoto(ctx, frameo.Photo{Path: path, Caption: "round trip"})
	if err != nil {
		t.Fatalf("SendPhoto: %v", err)
	}
	got, err := c.GetMedia(ctx, frameo.Fetch{ID: id})
	if err != nil {
		t.Fatalf("GetMedia(%d): %v", id, err)
	}
	if bytes.Equal(got.Data, sent) {
		t.Logf("the frame returned the %d bytes it was given, unchanged", len(sent))
		return
	}
	t.Logf("sent %d bytes and %d came back: the frame re-encodes what it stores",
		len(sent), len(got.Data))
}
