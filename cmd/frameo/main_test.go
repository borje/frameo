package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"frameo/internal/frameo"
	"frameo/internal/frameo/frameotest"
	"frameo/internal/frameo/pb"
	"frameo/internal/sdg/sdgtest"
)

// runCLI drives the command line exactly as main does, and returns what it
// printed.
func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := run(args, &out)
	return out.String(), err
}

// withConfig points the commands at a throwaway configuration file.
func withConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("FRAMEO_CONFIG", path)
	return path
}

// startFakeFrame brings up a grid, a relay and a frame, and returns the
// -server argument that reaches them along with the pairing code.
func startFakeFrame(t *testing.T, frame *frameotest.Frame) (server, code string) {
	t.Helper()
	grid, err := sdgtest.NewGrid()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := grid.Close(); err != nil {
			t.Errorf("fake grid reported: %v", err)
		}
	})

	const full = "12345678"
	handler := func(tun *sdgtest.Tunnel) {
		if err := frame.Serve(tun); err != nil {
			t.Errorf("fake frame reported: %v", err)
		}
	}
	// One device, reachable by code until it is paired and by address after.
	if _, err := grid.AddPairing(full[:len(full)-3], sdgtest.PairingDevice(full, nil), handler); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%s:%d", grid.Host(), grid.Port()), full
}

func TestWhoamiCreatesConfig(t *testing.T) {
	path := withConfig(t)

	out, err := runCLI(t, "whoami")
	if err != nil {
		t.Fatalf("whoami: %v", err)
	}
	if !strings.Contains(out, "Address") {
		t.Errorf("output does not report an address:\n%s", out)
	}

	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("whoami did not create a configuration: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("configuration permissions are %o, want 600", perm)
	}
}

func TestNoCommand(t *testing.T) {
	withConfig(t)
	if _, err := runCLI(t); err == nil {
		t.Error("want an error with no command")
	}
}

func TestUnknownCommand(t *testing.T) {
	withConfig(t)
	if _, err := runCLI(t, "frobnicate"); err == nil {
		t.Error("want an error for an unknown command")
	}
}

func TestCommandsNeedAPairedFrame(t *testing.T) {
	withConfig(t)
	for _, args := range [][]string{{"info"}, {"list"}, {"send", "x.jpg"}} {
		if _, err := runCLI(t, args...); err == nil {
			t.Errorf("%v should fail with nothing paired", args)
		}
	}
}

func TestSendChecksFilesBeforeConnecting(t *testing.T) {
	withConfig(t)
	// A missing file must be reported without a network round trip, so a
	// typo in a long batch fails immediately.
	_, err := runCLI(t, "-server", "127.0.0.1:1", "send", "/nonexistent/a.jpg")
	if err == nil || !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("err = %v, want it to name the missing file", err)
	}
}

func TestPairSendAndInspect(t *testing.T) {
	withConfig(t)
	frame := frameotest.New()
	frame.ListType = frameo.TypeGetAllMediaMetaData
	server, code := startFakeFrame(t, frame)

	out, err := runCLI(t, "-server", server, "pair", code)
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	if !strings.Contains(out, "Paired with") {
		t.Errorf("pair output:\n%s", out)
	}

	out, err = runCLI(t, "frames")
	if err != nil {
		t.Fatalf("frames: %v", err)
	}
	if !strings.Contains(out, "frame1") || !strings.Contains(out, "*") {
		t.Errorf("frames output does not show a default frame:\n%s", out)
	}

	out, err = runCLI(t, "-server", server, "info")
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	for _, want := range []string{"Test Frame", "1280 by 800"} {
		if !strings.Contains(out, want) {
			t.Errorf("info output does not mention %q:\n%s", want, out)
		}
	}

	photo := filepath.Join(t.TempDir(), "holiday.jpg")
	want := bytes.Repeat([]byte{0x42}, 40000)
	if err := os.WriteFile(photo, want, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err = runCLI(t, "-server", server, "-caption", "Sunset", "send", photo)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if !strings.Contains(out, "Sent") {
		t.Errorf("send output:\n%s", out)
	}

	photos := frame.Photos()
	if len(photos) != 1 {
		t.Fatalf("the frame holds %d photos, want 1", len(photos))
	}
	if !bytes.Equal(photos[0].Data, want) {
		t.Error("the frame received different bytes")
	}
	if got := photos[0].Media.GetCaption(); got != "Sunset" {
		t.Errorf("caption = %q, want Sunset", got)
	}

	out, err = runCLI(t, "-server", server, "list")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out, "holds no photos") {
		t.Errorf("list output:\n%s", out)
	}

	out, err = runCLI(t, "forget", "frame1")
	if err != nil {
		t.Fatalf("forget: %v", err)
	}
	if !strings.Contains(out, "Forgot frame1") {
		t.Errorf("forget output:\n%s", out)
	}
	if _, err := runCLI(t, "-server", server, "info"); err == nil {
		t.Error("info should fail after forgetting the only frame")
	}
}

func TestPairWithWrongCode(t *testing.T) {
	withConfig(t)
	frame := frameotest.New()
	server, _ := startFakeFrame(t, frame)

	if _, err := runCLI(t, "-server", server, "pair", "99999999"); err == nil {
		t.Error("want an error for a code the grid does not know")
	}
}

func TestSendSeveralPhotosFromTheCommandLine(t *testing.T) {
	withConfig(t)
	frame := frameotest.New()
	server, code := startFakeFrame(t, frame)

	if _, err := runCLI(t, "-server", server, "pair", code); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	var paths []string
	for i := range 3 {
		p := filepath.Join(dir, fmt.Sprintf("p%d.jpg", i))
		if err := os.WriteFile(p, bytes.Repeat([]byte{byte(i)}, 5000+i), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	args := append([]string{"-server", server, "send"}, paths...)
	out, err := runCLI(t, args...)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if got := strings.Count(out, "Sent"); got != 3 {
		t.Errorf("reported %d sends, want 3:\n%s", got, out)
	}
	if got := len(frame.Photos()); got != 3 {
		t.Errorf("the frame holds %d photos, want 3", got)
	}
}

// Listing's message number is known, so it works out of the box. Deleting's
// is not, so it refuses by default and takes a candidate from -type. This
// checks that path works, so that trying a candidate against a real frame is
// a matter of passing the flag.
func TestListAndDeleteWithASuppliedMessageNumber(t *testing.T) {
	withConfig(t)
	frame := frameotest.New()
	frame.ListType = frameo.TypeGetAllMediaMetaData
	frame.DeleteType = 34
	frame.Library = []*pb.MediaMetaData{
		{MediaId: 111, CaptureDate: 1600000000000, IsVisible: true},
		{MediaId: 222, CaptureDate: 1700000000000},
	}
	server, code := startFakeFrame(t, frame)

	if _, err := runCLI(t, "-server", server, "pair", code); err != nil {
		t.Fatal(err)
	}

	out, err := runCLI(t, "-server", server, "list")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, want := range []string{"111", "222", "shown", "hidden"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output does not mention %q:\n%s", want, out)
		}
	}

	if _, err := runCLI(t, "-server", server, "delete", "111"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got := frame.Deleted(); len(got) != 1 || got[0] != 111 {
		t.Errorf("frame was asked to delete %v, want [111]", got)
	}

	if _, err := runCLI(t, "-server", server, "delete", "notanumber"); err == nil {
		t.Error("want an error for an id that is not a number")
	}
}

// Hiding and showing go through the same path as deleting but leave the photo
// on the frame, so the listing still reports it.
func TestHideAndShow(t *testing.T) {
	withConfig(t)
	frame := frameotest.New()
	frame.ListType = frameo.TypeGetAllMediaMetaData
	frame.VisibilityType = frameo.TypeChangeMediaVisibility
	frame.Library = []*pb.MediaMetaData{{MediaId: 111, IsVisible: true}}
	server, code := startFakeFrame(t, frame)

	if _, err := runCLI(t, "-server", server, "pair", code); err != nil {
		t.Fatal(err)
	}

	if _, err := runCLI(t, "-server", server, "hide", "111"); err != nil {
		t.Fatalf("hide: %v", err)
	}
	out, err := runCLI(t, "-server", server, "list")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out, "111") || !strings.Contains(out, "hidden") {
		t.Errorf("want photo 111 listed as hidden:\n%s", out)
	}

	if _, err := runCLI(t, "-server", server, "show", "111"); err != nil {
		t.Fatalf("show: %v", err)
	}
	if out, err = runCLI(t, "-server", server, "list"); err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out, "shown") {
		t.Errorf("want photo 111 listed as shown:\n%s", out)
	}

	if _, err := runCLI(t, "-server", server, "hide", "notanumber"); err == nil {
		t.Error("want an error for an id that is not a number")
	}
	if _, err := runCLI(t, "-server", server, "hide"); err == nil {
		t.Error("want an error when no ids are given")
	}
}

// jpegBytes makes bytes that begin and end the way a JPEG does, since the
// client refuses a download that does not look like the photo it asked for.
func jpegBytes(size int, seed byte) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = seed + byte(i)
	}
	copy(data, []byte{0xff, 0xd8, 0xff})
	copy(data[size-2:], []byte{0xff, 0xd9})
	return data
}

func TestGetWritesPhotosToDisk(t *testing.T) {
	withConfig(t)
	frame := frameotest.New()
	frame.GetMediaType = frameo.TypeGetMedia
	one, two := jpegBytes(5000, 1), jpegBytes(3000, 40)
	frame.Servable = map[int64]frameotest.Servable{
		111: {Data: one, Extension: "jpg"},
		222: {Data: two, Extension: "jpg"},
	}
	server, code := startFakeFrame(t, frame)

	if _, err := runCLI(t, "-server", server, "pair", code); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	out, err := runCLI(t, "-server", server, "-out", dir, "get", "111", "222")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	for id, want := range map[int64][]byte{111: one, 222: two} {
		path := filepath.Join(dir, fmt.Sprintf("%d.jpg", id))
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v\n%s", path, err, out)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s holds %d bytes, want %d, and they differ", path, len(got), len(want))
		}
	}

	// A single photo may be named outright.
	named := filepath.Join(t.TempDir(), "chosen.jpg")
	if _, err := runCLI(t, "-server", server, "-out", named, "get", "111"); err != nil {
		t.Fatalf("get to a named file: %v", err)
	}
	if got, err := os.ReadFile(named); err != nil || !bytes.Equal(got, one) {
		t.Errorf("reading %s: %v", named, err)
	}
}

// TestGetKeepsGoingPastAMissingPhoto is the batch policy: one id that cannot be
// fetched costs that id and nothing else, and the run still reports failure.
func TestGetKeepsGoingPastAMissingPhoto(t *testing.T) {
	withConfig(t)
	frame := frameotest.New()
	frame.GetMediaType = frameo.TypeGetMedia
	want := jpegBytes(4000, 7)
	frame.Servable = map[int64]frameotest.Servable{222: {Data: want, Extension: "jpg"}}
	server, code := startFakeFrame(t, frame)

	if _, err := runCLI(t, "-server", server, "pair", code); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	// 111 is not on the frame; 222 is, and comes after it.
	_, err := runCLI(t, "-server", server, "-out", dir, "get", "111", "222")
	if err == nil {
		t.Error("want an error when a photo could not be fetched")
	}
	got, readErr := os.ReadFile(filepath.Join(dir, "222.jpg"))
	if readErr != nil {
		t.Fatalf("the photo after the missing one was not saved: %v", readErr)
	}
	if !bytes.Equal(got, want) {
		t.Error("222.jpg is not the photo the frame holds")
	}
	if _, err := os.Stat(filepath.Join(dir, "111.jpg")); err == nil {
		t.Error("a file was written for the photo that could not be fetched")
	}
}

func TestGetAllFetchesTheWholeListing(t *testing.T) {
	withConfig(t)
	frame := frameotest.New()
	frame.ListType = frameo.TypeGetAllMediaMetaData
	frame.GetMediaType = frameo.TypeGetMedia
	frame.Library = []*pb.MediaMetaData{
		{MediaId: 111, IsVisible: true},
		{MediaId: 222, IsVisible: true},
	}
	frame.Servable = map[int64]frameotest.Servable{
		111: {Data: jpegBytes(2000, 1), Extension: "jpg"},
		222: {Data: jpegBytes(2500, 9), Extension: "jpg"},
	}
	server, code := startFakeFrame(t, frame)

	if _, err := runCLI(t, "-server", server, "pair", code); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if _, err := runCLI(t, "-server", server, "-out", dir, "get", "all"); err != nil {
		t.Fatalf("get all: %v", err)
	}
	for _, name := range []string{"111.jpg", "222.jpg"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s was not written: %v", name, err)
		}
	}
	if got := frame.Served(); len(got) != 2 {
		t.Errorf("the frame was asked for %v, want both ids once each", got)
	}
}

// TestGetAllTreatsOutAsADirectory guards a batch of one. "all" is a batch
// whatever the frame happens to hold, so -out names where photos go and not
// what a single photo is called.
func TestGetAllTreatsOutAsADirectory(t *testing.T) {
	withConfig(t)
	frame := frameotest.New()
	frame.ListType = frameo.TypeGetAllMediaMetaData
	frame.GetMediaType = frameo.TypeGetMedia
	frame.Library = []*pb.MediaMetaData{{MediaId: 111, IsVisible: true}}
	frame.Servable = map[int64]frameotest.Servable{
		111: {Data: jpegBytes(2000, 1), Extension: "jpg"},
	}
	server, code := startFakeFrame(t, frame)

	if _, err := runCLI(t, "-server", server, "pair", code); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(t.TempDir(), "photos")
	if _, err := runCLI(t, "-server", server, "-out", dir, "get", "all"); err != nil {
		t.Fatalf("get all: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "111.jpg")); err != nil {
		t.Errorf("want the photo inside %s: %v", dir, err)
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		t.Errorf("%s should be a directory", dir)
	}
}

func TestPhotoFileName(t *testing.T) {
	// 2024-06-13T14:30:52Z.
	const taken = 1718289052000

	for _, c := range []struct {
		id    int64
		taken int64
		want  string
	}{
		{111, taken, "2024-06-13_143052_111.jpg"},
		// A frame that reports no capture date leaves the photo on its id.
		{111, 0, "111.jpg"},
		{0, 0, "0.jpg"},
		// A leading dash would be read as an option by most of the tools that
		// go on to handle the file.
		{-111, 0, "n111.jpg"},
		{-9223372036854775808, 0, "n9223372036854775808.jpg"},
		{-111, taken, "2024-06-13_143052_n111.jpg"},
	} {
		if got := photoFileName(c.id, c.taken, "jpg"); got != c.want {
			t.Errorf("photoFileName(%d, %d) = %q, want %q", c.id, c.taken, got, c.want)
		}
	}
}

// TestGetNamesPhotosByWhenTheyWereTaken checks the names sort into the order
// the photos were taken, which is the point of leading with the date.
func TestGetNamesPhotosByWhenTheyWereTaken(t *testing.T) {
	withConfig(t)
	frame := frameotest.New()
	frame.GetMediaType = frameo.TypeGetMedia
	frame.Servable = map[int64]frameotest.Servable{
		// The later photo has the lower id, so an id-ordered listing would put
		// these the other way round.
		111: {Data: jpegBytes(2000, 1), Extension: "jpg", CaptureDate: 1718289052000},
		222: {Data: jpegBytes(2000, 9), Extension: "jpg", CaptureDate: 1698948900000},
	}
	server, code := startFakeFrame(t, frame)

	if _, err := runCLI(t, "-server", server, "pair", code); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err := runCLI(t, "-server", server, "-out", dir, "get", "111", "222"); err != nil {
		t.Fatalf("get: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	// ReadDir sorts by name, so this is the order a directory listing shows.
	want := []string{"2023-11-02_181500_222.jpg", "2024-06-13_143052_111.jpg"}
	if !slices.Equal(names, want) {
		t.Errorf("directory holds %v, want %v", names, want)
	}
}

func TestNetFlagIsChecked(t *testing.T) {
	withConfig(t)
	// A mistyped -net must be caught before anything is attempted, since
	// falling back to a default would send a photo the long way round without
	// saying so.
	_, err := runCLI(t, "-net", "lan", "info")
	if err == nil || !strings.Contains(err.Error(), "lan") {
		t.Errorf("err = %v, want it to name the unusable -net value", err)
	}
	for _, how := range []string{"auto", "local", "relay"} {
		if _, err := runCLI(t, "-net", how); err == nil || strings.Contains(err.Error(), how) {
			t.Errorf("-net %s was rejected: %v", how, err)
		}
	}
}

func TestDiscoverFlagIsChecked(t *testing.T) {
	withConfig(t)
	// A window of zero or less is over before the first query goes out, which
	// turns every run into a relay run without saying so: the same silent
	// wrong route -net is checked to prevent.
	for _, window := range []string{"0", "-2s"} {
		if _, err := runCLI(t, "-discover", window, "info"); err == nil || !strings.Contains(err.Error(), "-discover") {
			t.Errorf("-discover %s: err = %v, want it to name the unusable window", window, err)
		}
	}
	if _, err := runCLI(t, "-discover", "1s"); err == nil || strings.Contains(err.Error(), "-discover") {
		t.Errorf("-discover 1s was rejected: %v", err)
	}
}

// TestNamedServerMeansTheRelay covers the rule that keeps these tests off the
// network: a grid named with -server is a deliberate route, so the local
// network is not searched unless -net asks for it.
func TestNamedServerMeansTheRelay(t *testing.T) {
	o := &options{network: networkAuto, server: "127.0.0.1:1"}
	if tryLocally(o) {
		t.Error("a named grid server still searched the local network")
	}
	o.network = networkLocal
	if !tryLocally(o) {
		t.Error("-net local did not search the local network")
	}
	if tryLocally(&options{network: networkRelay}) {
		t.Error("-net relay searched the local network")
	}
	if !tryLocally(&options{network: networkAuto}) {
		t.Error("the default did not search the local network")
	}
}
