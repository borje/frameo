package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

	// Listing needs a message number that is not known yet, so it must refuse
	// rather than send something the frame would misread.
	if _, err := runCLI(t, "-server", server, "list"); err == nil {
		t.Error("list should refuse until its message number is known")
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

// The numbers for listing and deleting are unknown, so both refuse by default
// and take a candidate from -type. This checks that path works, so that trying
// a candidate against a real frame is a matter of passing the flag.
func TestListAndDeleteWithASuppliedMessageNumber(t *testing.T) {
	withConfig(t)
	frame := frameotest.New()
	frame.ListType = 31
	frame.DeleteType = 34
	frame.Library = []*pb.MediaMetaData{
		{MediaId: 111, CaptureDate: 1600000000000, IsVisible: true},
		{MediaId: 222, CaptureDate: 1700000000000},
	}
	server, code := startFakeFrame(t, frame)

	if _, err := runCLI(t, "-server", server, "pair", code); err != nil {
		t.Fatal(err)
	}

	// Without a number, the command must refuse and say what to try.
	_, err := runCLI(t, "-server", server, "list")
	if err == nil {
		t.Fatal("list should refuse without a message number")
	}
	if !strings.Contains(err.Error(), "-type 31") {
		t.Errorf("the refusal does not suggest a candidate: %v", err)
	}

	out, err := runCLI(t, "-server", server, "-type", "31", "list")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, want := range []string{"111", "222", "shown", "hidden"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output does not mention %q:\n%s", want, out)
		}
	}

	if _, err := runCLI(t, "-server", server, "-type", "34", "delete", "111"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got := frame.Deleted(); len(got) != 1 || got[0] != 111 {
		t.Errorf("frame was asked to delete %v, want [111]", got)
	}

	if _, err := runCLI(t, "-server", server, "-type", "34", "delete", "notanumber"); err == nil {
		t.Error("want an error for an id that is not a number")
	}
}
