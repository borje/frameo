// SPDX-License-Identifier: GPL-3.0-or-later

package config_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/borje/frameo/internal/config"
	"github.com/borje/frameo/internal/sdg"
)

func tempPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "sub", "config.json")
}

// create makes a configuration where there is none, which is what pairing
// does. Load no longer creates one, so the tests that need a fresh identity
// ask for it.
func create(path string) (*config.Config, error) {
	c, _, err := config.Create(path)
	return c, err
}

func TestCreateMakesAnIdentity(t *testing.T) {
	path := tempPath(t)
	c, err := create(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	id, err := c.Identity()
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if id.Public == (sdg.Key{}) {
		t.Error("public key is empty")
	}

	// The file holds the key a frame is paired to, so it must not be readable
	// by anyone else.
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("permissions are %o, want 600", perm)
	}

	again, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	id2, _ := again.Identity()
	if id2.Private != id.Private {
		t.Error("reloading produced a different identity")
	}
}

func TestAddAndResolveFrames(t *testing.T) {
	c, err := create(tempPath(t))
	if err != nil {
		t.Fatal(err)
	}

	var living, kitchen sdg.PeerID
	living[0], kitchen[0] = 1, 2

	if _, err := c.AddFrame("living", living); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddFrame("kitchen", kitchen); err != nil {
		t.Fatal(err)
	}

	// The first frame paired becomes the default, so the common case of one
	// frame needs no naming.
	name, peer, err := c.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	if name != "living" || peer != living {
		t.Errorf("default resolved to %q/%s", name, peer)
	}

	if _, peer, err = c.Resolve("kitchen"); err != nil || peer != kitchen {
		t.Errorf("Resolve(kitchen) = %s, %v", peer, err)
	}
	if _, _, err := c.Resolve("bedroom"); err == nil {
		t.Error("want an error for an unknown frame")
	}

	if got := c.Names(); len(got) != 2 || got[0] != "kitchen" || got[1] != "living" {
		t.Errorf("Names() = %v, want a sorted list", got)
	}
}

func TestResolveWithNothingPaired(t *testing.T) {
	c, err := create(tempPath(t))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = c.Resolve("")
	if err == nil {
		t.Fatal("want an error when nothing is paired")
	}
	// The message has to tell someone what to do next.
	if want := "frameo pair"; !contains(err.Error(), want) {
		t.Errorf("error %q does not mention %q", err, want)
	}
}

func TestAutoNaming(t *testing.T) {
	c, err := create(tempPath(t))
	if err != nil {
		t.Fatal(err)
	}
	var a, b sdg.PeerID
	a[0], b[0] = 1, 2
	if _, err := c.AddFrame("", a); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddFrame("", b); err != nil {
		t.Fatal(err)
	}
	if got := c.Names(); len(got) != 2 || got[0] != "frame1" || got[1] != "frame2" {
		t.Errorf("Names() = %v", got)
	}
}

func TestRemoveFrameMovesTheDefault(t *testing.T) {
	c, err := create(tempPath(t))
	if err != nil {
		t.Fatal(err)
	}
	var a, b sdg.PeerID
	a[0], b[0] = 1, 2
	_, _ = c.AddFrame("one", a)
	_, _ = c.AddFrame("two", b)

	if err := c.RemoveFrame("one"); err != nil {
		t.Fatal(err)
	}
	name, _, err := c.Resolve("")
	if err != nil || name != "two" {
		t.Errorf("after removing the default, Resolve gave %q, %v", name, err)
	}
	if err := c.RemoveFrame("gone"); err == nil {
		t.Error("want an error removing a frame that is not there")
	}
}

func TestPairingSurvivesReload(t *testing.T) {
	path := tempPath(t)
	c, err := create(path)
	if err != nil {
		t.Fatal(err)
	}
	var peer sdg.PeerID
	peer[0] = 0xab
	if _, err := c.AddFrame("living", peer); err != nil {
		t.Fatal(err)
	}

	again, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	_, got, err := again.Resolve("living")
	if err != nil || got != peer {
		t.Errorf("after reload, Resolve gave %s, %v", got, err)
	}
}

func TestLoadRejectsCorruptFile(t *testing.T) {
	dir := t.TempDir()

	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(bad); err == nil {
		t.Error("want an error for unreadable JSON")
	}

	shortKey := filepath.Join(dir, "short.json")
	data, _ := json.Marshal(map[string]string{"private_key": "abcd"})
	if err := os.WriteFile(shortKey, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(shortKey); err == nil {
		t.Error("want an error for an unusable private key")
	}
}

func TestDefaultPathHonoursOverride(t *testing.T) {
	t.Setenv("FRAMEO_CONFIG", "/tmp/somewhere/frameo.json")
	got, err := config.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if got != "/tmp/somewhere/frameo.json" {
		t.Errorf("DefaultPath() = %q", got)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// Pairing a frame that is already known must update it, not create a second
// entry pointing at the same device.
func TestRepairingTheSameFrame(t *testing.T) {
	c, err := create(tempPath(t))
	if err != nil {
		t.Fatal(err)
	}
	var peer sdg.PeerID
	peer[0] = 0x7f

	first, err := c.AddFrame("", peer)
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.AddFrame("", peer)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("re-pairing produced %q then %q", first, second)
	}
	if got := len(c.Frames); got != 1 {
		t.Errorf("configuration holds %d frames, want 1: %v", got, c.Names())
	}
}

func TestRenamingAFrameDropsTheOldEntry(t *testing.T) {
	c, err := create(tempPath(t))
	if err != nil {
		t.Fatal(err)
	}
	var peer sdg.PeerID
	peer[0] = 0x11
	if _, err := c.AddFrame("", peer); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddFrame("hallway", peer); err != nil {
		t.Fatal(err)
	}
	if got := c.Names(); len(got) != 1 || got[0] != "hallway" {
		t.Errorf("Names() = %v, want just the new name", got)
	}
	if _, _, err := c.Resolve(""); err != nil {
		t.Errorf("the default frame did not follow the rename: %v", err)
	}
}

// A missing configuration means one of two different things, and they need
// different answers: a first run wants an identity created, a lost one wants
// its file back, because the key it held cannot be recreated.
func TestMissingTellsAFirstRunFromALostConfiguration(t *testing.T) {
	t.Setenv("FRAMEO_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	path, err := config.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(path, os.Getenv("XDG_CONFIG_HOME")) {
		t.Skip("the user config dir does not follow the environment on this platform")
	}

	var miss *config.Missing
	if _, err := config.Load(""); !errors.As(err, &miss) {
		t.Fatalf("Load of a first run: err = %v, want *config.Missing", err)
	} else if miss.Orphaned {
		t.Error("a first run was reported as a lost configuration")
	}

	if _, _, err := config.Create(""); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	if _, err := config.Load(""); !errors.As(err, &miss) {
		t.Fatalf("Load after removal: err = %v, want *config.Missing", err)
	} else if !miss.Orphaned {
		t.Error("a configuration that was written and removed was reported as a first run")
	}
}

// The directory is evidence only where we own it. A path given with -config
// sits in a directory that exists for its own reasons and proves nothing, so
// claiming a key was lost there would be an invention.
func TestAGivenPathNeverClaimsALostConfiguration(t *testing.T) {
	_, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
	var miss *config.Missing
	if !errors.As(err, &miss) {
		t.Fatalf("err = %v, want *config.Missing", err)
	}
	if miss.Orphaned {
		t.Error("an existing directory we do not own was read as a lost configuration")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Error("a missing configuration does not report as os.ErrNotExist")
	}
}
