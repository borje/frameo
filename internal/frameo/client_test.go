package frameo_test

import (
	"bytes"
	"context"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
	"time"

	"frameo/internal/frameo"
	"frameo/internal/frameo/frameotest"
	"frameo/internal/frameo/pb"
	"frameo/internal/sdg"
	"frameo/internal/sdg/sdgtest"
	"google.golang.org/protobuf/proto"
)

// setup wires a real client to a fake frame through the real transport and a
// fake grid, so every layer under test is the one that ships.
func setup(t *testing.T, frame *frameotest.Frame) *frameo.Client {
	t.Helper()

	grid, err := sdgtest.NewGrid()
	if err != nil {
		t.Fatalf("start fake grid: %v", err)
	}
	t.Cleanup(func() {
		if err := grid.Close(); err != nil {
			t.Errorf("fake grid reported: %v", err)
		}
	})

	frameErrs := make(chan error, 4)
	peerID, err := grid.AddDevice(func(tun *sdgtest.Tunnel) {
		if err := frame.Serve(tun); err != nil {
			frameErrs <- err
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		select {
		case err := <-frameErrs:
			t.Errorf("fake frame reported: %v", err)
		default:
		}
	})

	id, err := sdg.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	g, err := sdg.Dial(ctx, []sdg.Endpoint{{Host: grid.Host(), Port: grid.Port()}}, id, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = g.Close() })

	p, err := g.Connect(ctx, sdg.PeerID(peerID), sdg.FrameoProtocol)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	c := frameo.NewClient(p, nil)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// writePhoto creates a file of pseudo-random bytes standing in for a photo.
func writePhoto(t *testing.T, size int) string {
	t.Helper()
	data := make([]byte, size)
	rnd := rand.New(rand.NewPCG(7, uint64(size)))
	for i := range data {
		data[i] = byte(rnd.UintN(256))
	}
	path := filepath.Join(t.TempDir(), "photo.jpg")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGetInfo(t *testing.T) {
	frame := frameotest.New()
	c := setup(t, frame)

	info, err := c.GetInfo(testCtx(t))
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	if info.GetName() != "Test Frame" {
		t.Errorf("name = %q", info.GetName())
	}
	if info.GetScreenWidth() != 1280 || info.GetScreenHeight() != 800 {
		t.Errorf("screen = %dx%d", info.GetScreenWidth(), info.GetScreenHeight())
	}
}

func TestSendPhoto(t *testing.T) {
	// Sizes either side of a segment boundary, plus one large enough that the
	// header alone would not fit in a single transport message.
	for _, size := range []int{1, 16000, 16001, 100 << 10} {
		frame := frameotest.New()
		c := setup(t, frame)
		path := writePhoto(t, size)
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}

		id, err := c.SendPhoto(testCtx(t), frameo.Photo{Path: path, Caption: "hello"})
		if err != nil {
			t.Fatalf("size %d: SendPhoto: %v", size, err)
		}

		photos := frame.Photos()
		if len(photos) != 1 {
			t.Fatalf("size %d: frame holds %d photos, want 1", size, len(photos))
		}
		got := photos[0]
		if !bytes.Equal(got.Data, want) {
			t.Errorf("size %d: the frame received different bytes", size)
		}
		if got.Media.GetId() != id {
			t.Errorf("size %d: frame filed the photo under %d, we reported %d", size, got.Media.GetId(), id)
		}
		if int(got.Media.GetSize()) != size {
			t.Errorf("size %d: header declared %d bytes", size, got.Media.GetSize())
		}
		if got.Media.GetCaption() != "hello" {
			t.Errorf("size %d: caption = %q", size, got.Media.GetCaption())
		}
		if got.Media.GetFileExtension() != "jpg" {
			t.Errorf("size %d: extension = %q", size, got.Media.GetFileExtension())
		}
	}
}

func TestSendPhotoSegmentsByDefault(t *testing.T) {
	frame := frameotest.New()
	c := setup(t, frame)
	path := writePhoto(t, 50<<10)

	if _, err := c.SendPhoto(testCtx(t), frameo.Photo{Path: path}); err != nil {
		t.Fatal(err)
	}
	// 50 KiB at 16000 bytes per segment is four segments, matching how the app
	// splits a file rather than relying on the transport to split it.
	if got := frame.Segments(); got != 4 {
		t.Errorf("frame saw %d segments, want 4", got)
	}
}

func TestSendPhotoSingleSegment(t *testing.T) {
	frame := frameotest.New()
	c := setup(t, frame)
	path := writePhoto(t, 50<<10)
	want, _ := os.ReadFile(path)

	if _, err := c.SendPhoto(testCtx(t), frameo.Photo{Path: path, SingleSegment: true}); err != nil {
		t.Fatal(err)
	}
	if got := frame.Segments(); got != 1 {
		t.Errorf("frame saw %d segments, want 1", got)
	}
	photos := frame.Photos()
	if len(photos) != 1 || !bytes.Equal(photos[0].Data, want) {
		t.Error("the photo did not survive being sent as one oversized message")
	}
}

func TestSendPhotoMetadata(t *testing.T) {
	frame := frameotest.New()
	c := setup(t, frame)
	path := writePhoto(t, 1000)
	taken := time.Date(2021, 6, 5, 12, 0, 0, 0, time.UTC)

	if _, err := c.SendPhoto(testCtx(t), frameo.Photo{
		Path: path, Taken: taken, Fit: true, Center: &[2]float32{0.25, 0.75},
	}); err != nil {
		t.Fatal(err)
	}
	m := frame.Photos()[0].Media
	if m.GetCaptureDate() != taken.UnixMilli() {
		t.Errorf("capture date = %d, want %d", m.GetCaptureDate(), taken.UnixMilli())
	}
	if m.GetScaleType() != 1 { // fit inside
		t.Errorf("scale type = %v, want fit inside", m.GetScaleType())
	}
	if m.GetCenterPointX() != 0.25 || m.GetCenterPointY() != 0.75 {
		t.Errorf("centre point = %v,%v", m.GetCenterPointX(), m.GetCenterPointY())
	}
}

func TestSendPhotoDefaultsCaptureDateToFileTime(t *testing.T) {
	frame := frameotest.New()
	c := setup(t, frame)
	path := writePhoto(t, 500)
	when := time.Date(2019, 3, 2, 9, 30, 0, 0, time.UTC)
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}

	if _, err := c.SendPhoto(testCtx(t), frameo.Photo{Path: path}); err != nil {
		t.Fatal(err)
	}
	if got := frame.Photos()[0].Media.GetCaptureDate(); got != when.UnixMilli() {
		t.Errorf("capture date = %d, want the file's own time %d", got, when.UnixMilli())
	}
}

func TestSendPhotoReportsFrameError(t *testing.T) {
	frame := frameotest.New()
	frame.RefuseTransfers = true
	c := setup(t, frame)
	path := writePhoto(t, 2000)

	_, err := c.SendPhoto(testCtx(t), frameo.Photo{Path: path})
	if err == nil {
		t.Fatal("want an error when the frame refuses the transfer")
	}
	t.Logf("reported: %v", err)
}

func TestSendPhotoTimesOutWithoutAck(t *testing.T) {
	frame := frameotest.New()
	frame.DropAck = true
	c := setup(t, frame)
	path := writePhoto(t, 1000)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := c.SendPhoto(ctx, frameo.Photo{Path: path}); err == nil {
		t.Error("want an error when the frame never confirms")
	}
}

func TestSendPhotoRejectsMissingFile(t *testing.T) {
	frame := frameotest.New()
	c := setup(t, frame)
	if _, err := c.SendPhoto(testCtx(t), frameo.Photo{Path: "/nonexistent/photo.jpg"}); err == nil {
		t.Error("want an error for a missing file")
	}
}

func TestSendPhotoRejectsEmptyFile(t *testing.T) {
	frame := frameotest.New()
	c := setup(t, frame)
	path := filepath.Join(t.TempDir(), "empty.jpg")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SendPhoto(testCtx(t), frameo.Photo{Path: path}); err == nil {
		t.Error("want an error for an empty file")
	}
}

func TestSendSeveralPhotos(t *testing.T) {
	frame := frameotest.New()
	c := setup(t, frame)
	ctx := testCtx(t)

	for i := range 3 {
		path := writePhoto(t, 20000+i)
		if _, err := c.SendPhoto(ctx, frameo.Photo{Path: path}); err != nil {
			t.Fatalf("photo %d: %v", i, err)
		}
	}
	if got := len(frame.Photos()); got != 3 {
		t.Errorf("frame holds %d photos, want 3", got)
	}
	ids := map[int64]bool{}
	for _, p := range frame.Photos() {
		if ids[p.Media.GetId()] {
			t.Errorf("two photos share the id %d", p.Media.GetId())
		}
		ids[p.Media.GetId()] = true
	}
}

func TestDeleteMedia(t *testing.T) {
	frame := frameotest.New()
	frame.DeleteType = frameo.TypeDeleteMedia
	c := setup(t, frame)
	ctx := testCtx(t)

	if err := c.DeleteMedia(ctx, []int64{1, 2}, 0); err != nil {
		t.Fatalf("DeleteMedia: %v", err)
	}
	if got := frame.Deleted(); len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Errorf("frame was asked to delete %v, want [1 2]", got)
	}
	// Nothing to do is not an error, and must not reach the frame.
	if err := c.DeleteMedia(ctx, nil, 0); err != nil {
		t.Errorf("DeleteMedia with no ids = %v, want nil", err)
	}
	if got := frame.Deleted(); len(got) != 2 {
		t.Errorf("an empty deletion still reached the frame: %v", got)
	}
}

// Hiding a photo keeps it on the frame, which is what separates it from
// deleting: the listing still reports the photo, marked hidden.
func TestSetMediaVisible(t *testing.T) {
	frame := frameotest.New()
	frame.ListType = frameo.TypeGetAllMediaMetaData
	frame.VisibilityType = frameo.TypeChangeMediaVisibility
	frame.Library = []*pb.MediaMetaData{
		{MediaId: 1, IsVisible: true},
		{MediaId: 2, IsVisible: true},
	}
	c := setup(t, frame)
	ctx := testCtx(t)

	if err := c.SetMediaVisible(ctx, []int64{1}, false, 0); err != nil {
		t.Fatalf("SetMediaVisible: %v", err)
	}
	items, err := c.ListMedia(ctx)
	if err != nil {
		t.Fatalf("ListMedia: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("got %d items, want the hidden photo to still be listed", len(items))
	}
	if items[0].GetIsVisible() {
		t.Errorf("photo 1 is still visible")
	}
	if !items[1].GetIsVisible() {
		t.Errorf("photo 2 was hidden too, and should not have been")
	}

	if err := c.SetMediaVisible(ctx, []int64{1}, true, 0); err != nil {
		t.Fatalf("SetMediaVisible back: %v", err)
	}
	if items, err = c.ListMedia(ctx); err != nil {
		t.Fatalf("ListMedia: %v", err)
	}
	if !items[0].GetIsVisible() {
		t.Errorf("photo 1 was not shown again")
	}
}

// An override still wins, so a candidate number can be tried against a real
// frame without editing the constant.
func TestSetMediaVisibleHonoursTypeOverride(t *testing.T) {
	frame := frameotest.New()
	frame.VisibilityType = 99
	frame.Library = []*pb.MediaMetaData{{MediaId: 1, IsVisible: true}}
	c := setup(t, frame)

	if err := c.SetMediaVisible(testCtx(t), []int64{1}, false, 99); err != nil {
		t.Fatalf("SetMediaVisible: %v", err)
	}
	if frame.Library[0].GetIsVisible() {
		t.Errorf("the frame did not apply the change sent on the override number")
	}
}

func TestListMedia(t *testing.T) {
	frame := frameotest.New()
	frame.ListType = frameo.TypeGetAllMediaMetaData
	frame.Library = []*pb.MediaMetaData{
		{MediaId: 1, CaptureDate: 1000, IsVisible: true},
		{MediaId: 2, CaptureDate: 2000, IsVisible: false},
	}
	c := setup(t, frame)

	items, err := c.ListMedia(testCtx(t))
	if err != nil {
		t.Fatalf("ListMedia: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("got %d items, want 2", len(items))
	}
	if items[0].GetMediaId() != 1 || items[1].GetMediaId() != 2 {
		t.Errorf("items = %+v, want ids 1 and 2 in order", items)
	}
}

func TestSendRawReachesTheFrame(t *testing.T) {
	frame := frameotest.New()
	c := setup(t, frame)

	if err := c.SendRaw(testCtx(t), 99, nil); err != nil {
		t.Fatalf("SendRaw: %v", err)
	}
	deadline := time.After(5 * time.Second)
	for {
		if got := frame.UnknownTypes(); len(got) > 0 {
			if got[0] != 99 {
				t.Errorf("frame saw message number %d, want 99", got[0])
			}
			return
		}
		select {
		case <-deadline:
			t.Fatal("the frame never saw the message")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestOperationFailsAfterClose(t *testing.T) {
	frame := frameotest.New()
	c := setup(t, frame)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetInfo(testCtx(t)); err == nil {
		t.Error("want an error after closing")
	}
}

func TestSendPhotoCropFocus(t *testing.T) {
	t.Run("defaults to the middle", func(t *testing.T) {
		frame := frameotest.New()
		c := setup(t, frame)
		if _, err := c.SendPhoto(testCtx(t), frameo.Photo{Path: writePhoto(t, 500)}); err != nil {
			t.Fatal(err)
		}
		m := frame.Photos()[0].Media
		if m.GetCenterPointX() != 0.5 || m.GetCenterPointY() != 0.5 {
			t.Errorf("centre point = %v,%v, want 0.5,0.5", m.GetCenterPointX(), m.GetCenterPointY())
		}
	})

	// The top-left corner is a legitimate focus and must not be mistaken for
	// "not specified".
	t.Run("top left corner", func(t *testing.T) {
		frame := frameotest.New()
		c := setup(t, frame)
		photo := frameo.Photo{Path: writePhoto(t, 500), Center: &[2]float32{0, 0}}
		if _, err := c.SendPhoto(testCtx(t), photo); err != nil {
			t.Fatal(err)
		}
		m := frame.Photos()[0].Media
		if m.GetCenterPointX() != 0 || m.GetCenterPointY() != 0 {
			t.Errorf("centre point = %v,%v, want 0,0", m.GetCenterPointX(), m.GetCenterPointY())
		}
	})
}

// A failed acknowledgement belongs to one transfer. It must not end an
// unrelated wait, or sending several photos would report the wrong one as
// having failed.
func TestUnrelatedFailedAckDoesNotDerailAnotherWait(t *testing.T) {
	frame := frameotest.New()
	c := setup(t, frame)
	ctx := testCtx(t)

	// A stray failure arrives before the request we care about is answered.
	if err := c.SendRaw(ctx, 6, mustAck(t, 999999, 7)); err != nil {
		t.Fatal(err)
	}
	info, err := c.GetInfo(ctx)
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	if info.GetName() != "Test Frame" {
		t.Errorf("name = %q", info.GetName())
	}
}

// mustAck builds an acknowledgement carrying an error, as the frame would.
func mustAck(t *testing.T, id int64, code int32) []byte {
	t.Helper()
	b, err := proto.Marshal(&pb.AcknowledgeReceipt{
		AcknowledgeId: id,
		Error:         &pb.Error{Code: pb.Error_Code(code)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
