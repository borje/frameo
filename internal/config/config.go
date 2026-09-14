// Package config stores this client's identity and the frames it has paired
// with.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	"frameo/internal/sdg"
)

// Config is the on-disk state. The private key is the client's identity: a
// frame is paired to it, so losing the file means pairing every frame again.
type Config struct {
	PrivateKey   string           `json:"private_key"`
	DefaultFrame string           `json:"default_frame,omitempty"`
	Frames       map[string]Frame `json:"frames,omitempty"`

	path string
}

// Frame is one paired device.
type Frame struct {
	PeerID   string    `json:"peer_id"`
	Name     string    `json:"name,omitempty"`
	PairedAt time.Time `json:"paired_at,omitempty"`
}

// DefaultPath is where the configuration lives, honouring the FRAMEO_CONFIG
// override.
func DefaultPath() (string, error) {
	if p := os.Getenv("FRAMEO_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("config: cannot locate a configuration directory: %w", err)
	}
	return filepath.Join(dir, "frameo", "config.json"), nil
}

// Load reads the configuration, creating it with a fresh identity if it does
// not exist yet.
func Load(path string) (*Config, error) {
	if path == "" {
		var err error
		if path, err = DefaultPath(); err != nil {
			return nil, err
		}
	}

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		id, err := sdg.NewIdentity()
		if err != nil {
			return nil, err
		}
		c := &Config{PrivateKey: id.Private.String(), Frames: map[string]Frame{}, path: path}
		if err := c.Save(); err != nil {
			return nil, err
		}
		return c, nil
	}
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("config: %s is not readable: %w", path, err)
	}
	c.path = path
	if c.Frames == nil {
		c.Frames = map[string]Frame{}
	}
	if _, err := c.Identity(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Path is where this configuration was loaded from.
func (c *Config) Path() string { return c.path }

// Identity returns the client's key pair.
func (c *Config) Identity() (*sdg.Identity, error) {
	k, err := sdg.ParseKey(c.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("config: %s holds an unusable private key: %w", c.path, err)
	}
	return sdg.IdentityFromPrivate(k), nil
}

// Save writes the configuration back. The file holds a private key, so it is
// written only for its owner, and through a temporary file so a failure
// part-way cannot leave an unusable identity behind.
func (c *Config) Save() error {
	if c.path == "" {
		return errors.New("config: no path to save to")
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	data = append(data, '\n')

	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if err := os.Rename(tmp, c.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("config: %w", err)
	}
	return nil
}

// AddFrame records a pairing and returns the name it was filed under. Pairing
// a frame that is already known updates it in place rather than adding a
// second entry for the same device.
func (c *Config) AddFrame(name string, peer sdg.PeerID) (string, error) {
	if name == "" {
		name = c.nameFor(peer)
	}
	// Two names for one device would make the address ambiguous, so drop any
	// other entry pointing at it.
	for n, f := range c.Frames {
		if f.PeerID == peer.String() && n != name {
			delete(c.Frames, n)
			if c.DefaultFrame == n {
				c.DefaultFrame = name
			}
		}
	}
	c.Frames[name] = Frame{PeerID: peer.String(), Name: name, PairedAt: time.Now().UTC()}
	if c.DefaultFrame == "" {
		c.DefaultFrame = name
	}
	return name, c.Save()
}

// RemoveFrame forgets a pairing.
func (c *Config) RemoveFrame(name string) error {
	if _, ok := c.Frames[name]; !ok {
		return fmt.Errorf("config: no frame named %q", name)
	}
	delete(c.Frames, name)
	if c.DefaultFrame == name {
		c.DefaultFrame = ""
		if names := c.Names(); len(names) > 0 {
			c.DefaultFrame = names[0]
		}
	}
	return c.Save()
}

// Names lists the paired frames in a stable order.
func (c *Config) Names() []string { return slices.Sorted(maps.Keys(c.Frames)) }

// Resolve finds a frame by name, or the default when no name is given.
func (c *Config) Resolve(name string) (string, sdg.PeerID, error) {
	var zero sdg.PeerID
	if name == "" {
		name = c.DefaultFrame
	}
	if name == "" {
		if len(c.Frames) == 0 {
			return "", zero, errors.New("no frame is paired yet: run \"frameo pair\" with the code the frame is showing")
		}
		return "", zero, fmt.Errorf("no default frame is set: name one of %v", c.Names())
	}
	f, ok := c.Frames[name]
	if !ok {
		return "", zero, fmt.Errorf("no frame named %q: known frames are %v", name, c.Names())
	}
	peer, err := sdg.ParseKey(f.PeerID)
	if err != nil {
		return "", zero, fmt.Errorf("frame %q has an unusable peer id: %w", name, err)
	}
	return name, peer, nil
}

// nameFor picks a name for a frame the user did not name: the one it already
// has if it is known, otherwise the next unused one.
func (c *Config) nameFor(peer sdg.PeerID) string {
	for n, f := range c.Frames {
		if f.PeerID == peer.String() {
			return n
		}
	}
	for i := 1; ; i++ {
		name := fmt.Sprintf("frame%d", i)
		if _, taken := c.Frames[name]; !taken {
			return name
		}
	}
}
