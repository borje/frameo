// Command frameo sends photos to a Frameo digital photo frame.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"frameo/internal/config"
	"frameo/internal/frameo"
	"frameo/internal/sdg"
)

const usage = `frameo sends photos to a Frameo digital photo frame.

Usage:
  frameo [options] <command> [arguments]

Commands:
  pair <code>        pair with the frame showing this code
  info               describe the frame
  send <file|url>... send photos, from disk or from the web
  list               list the photos on the frame
  get <id>... | all  copy photos off the frame into files
  hide <id>...       hide photos without removing them
  show <id>...       show photos that were hidden
  delete <id>...     remove photos from the frame
  frames             list paired frames
  forget <name>      forget a paired frame
  whoami             print this client's own identity
  raw <number>       send an empty message with the given number and report replies

Options:
  -frame <name>      which paired frame to use (default: the first one paired)
  -caption <text>    caption to send with a photo
  -out <path>        where get writes: a file for one photo, a directory for many
  -size <pixels>     ask get for a copy scaled to fit this square
  -wait <dur>        how long get waits for one photo before asking again (default 6s)
  -fit               fit the whole photo on screen instead of cropping to fill
  -single-segment    send each photo as one message instead of a series
  -timeout <dur>     give up after this long, covering the whole run (default 15m)
  -config <path>     configuration file (default: under the user config dir)
  -server <host:port>  use this grid server instead of Frameo's
  -v                 log the protocol exchange

send takes an http or https URL wherever it takes a path. Every photo is
fetched before the frame is connected to, so a link that does not answer
costs nothing, and the format is read off the photo itself, falling back to
what the server called it and then to the URL's own extension.

get writes each photo as <date>_<time>_<id>.<extension> in the current
directory unless -out says otherwise, so a directory of them sorts into the
order the photos were taken. A frame that reports no capture date leaves the
photo named by its id alone. get keeps going past a photo it cannot fetch, so
one missing id does not cost the rest.

delete removes a photo for good; hide keeps it on the frame and stops it
being displayed. See internal/frameo/types.go for what is known of the
protocol, including the one message number still missing and the one taken
from a decompile that no frame has yet confirmed.
`

type options struct {
	out           io.Writer
	frame         string
	caption       string
	outPath       string
	size          int
	wait          time.Duration
	fit           bool
	singleSegment bool
	timeout       time.Duration
	configPath    string
	server        string
	verbose       bool
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "frameo:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	o := options{out: stdout}
	fs := flag.NewFlagSet("frameo", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	fs.StringVar(&o.frame, "frame", "", "which paired frame to use")
	fs.StringVar(&o.caption, "caption", "", "caption to send with a photo")
	fs.StringVar(&o.outPath, "out", "", "where get writes")
	fs.IntVar(&o.size, "size", 0, "ask get for a copy scaled to fit this square")
	fs.DurationVar(&o.wait, "wait", 0, "how long get waits for one photo before asking again")
	fs.BoolVar(&o.fit, "fit", false, "fit the whole photo on screen")
	fs.BoolVar(&o.singleSegment, "single-segment", false, "send each photo as one message")
	fs.DurationVar(&o.timeout, "timeout", 15*time.Minute, "give up after this long")
	fs.StringVar(&o.configPath, "config", "", "configuration file")
	fs.StringVar(&o.server, "server", "", "grid server to use")
	fs.BoolVar(&o.verbose, "v", false, "log the protocol exchange")
	if err := fs.Parse(args); err != nil {
		return errors.New("run \"frameo\" with no arguments for usage")
	}

	args = fs.Args()
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("no command given")
	}

	cmdName := args[0]
	// Handled before the configuration is touched, so a typo or a request for
	// help does not create an identity file as a side effect.
	switch cmdName {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return nil
	}
	if !knownCommands[cmdName] {
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", cmdName)
	}

	cfg, err := config.Load(o.configPath)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "pair":
		return cmdPair(ctx, cfg, &o, rest)
	case "info":
		return cmdInfo(ctx, cfg, &o)
	case "send":
		return cmdSend(ctx, cfg, &o, rest)
	case "list":
		return cmdList(ctx, cfg, &o)
	case "get":
		return cmdGet(ctx, cfg, &o, rest)
	case "hide":
		return cmdSetVisible(ctx, cfg, &o, rest, false)
	case "show":
		return cmdSetVisible(ctx, cfg, &o, rest, true)
	case "delete":
		return cmdDelete(ctx, cfg, &o, rest)
	case "frames":
		return cmdFrames(cfg, &o)
	case "forget":
		return cmdForget(cfg, &o, rest)
	case "whoami":
		return cmdWhoami(cfg, &o)
	case "raw":
		return cmdRaw(ctx, cfg, &o, rest)
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

// knownCommands is checked before anything is read or written, so an unknown
// command has no side effects.
var knownCommands = map[string]bool{
	"pair": true, "info": true, "send": true, "list": true, "delete": true,
	"get":  true,
	"hide": true, "show": true,
	"frames": true, "forget": true, "whoami": true, "raw": true,
}

// logger builds the protocol logger. Quiet by default, because the ordinary
// output of these commands is the answer, not a trace.
func (o *options) logger() *slog.Logger {
	level := slog.LevelWarn
	if o.verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// endpoints returns the grid servers to try.
func (o *options) endpoints() ([]sdg.Endpoint, []sdg.Key, error) {
	if o.server == "" {
		return sdg.FrameoServers, []sdg.Key{sdg.FrameoServerKey}, nil
	}
	host, portStr, err := splitHostPort(o.server)
	if err != nil {
		return nil, nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, nil, fmt.Errorf("bad port in %q", o.server)
	}
	// A server named explicitly is a test server, so its key is not pinned.
	return []sdg.Endpoint{{Host: host, Port: port}}, nil, nil
}

func splitHostPort(s string) (string, string, error) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", "", fmt.Errorf("expected host:port, got %q", s)
	}
	return strings.Trim(s[:i], "[]"), s[i+1:], nil
}

// dialGrid opens a grid connection using the stored identity.
func dialGrid(ctx context.Context, cfg *config.Config, o *options) (*sdg.Grid, error) {
	id, err := cfg.Identity()
	if err != nil {
		return nil, err
	}
	servers, keys, err := o.endpoints()
	if err != nil {
		return nil, err
	}
	return sdg.Dial(ctx, servers, id, &sdg.Options{
		Logger:     o.logger(),
		ServerKeys: keys,
	})
}

// connect opens a conversation with a paired frame.
func connect(ctx context.Context, cfg *config.Config, o *options) (*frameo.Client, string, error) {
	name, peer, err := cfg.Resolve(o.frame)
	if err != nil {
		return nil, "", err
	}
	g, err := dialGrid(ctx, cfg, o)
	if err != nil {
		return nil, "", err
	}
	p, err := g.Connect(ctx, peer, sdg.FrameoProtocol)
	if err != nil {
		_ = g.Close()
		if errors.Is(err, sdg.ErrPeerTimeout) {
			return nil, "", fmt.Errorf("frame %q did not answer: it may be switched off or off the network", name)
		}
		if errors.Is(err, sdg.ErrRefused) {
			return nil, "", fmt.Errorf("frame %q refused the connection: the pairing may have been removed on the frame", name)
		}
		return nil, "", err
	}
	// The peer connection stands on its own, but the grid connection is no
	// longer needed once it is up.
	go func() {
		<-p.Done()
		_ = g.Close()
	}()
	return frameo.NewClient(p, o.logger()), name, nil
}

func cmdPair(ctx context.Context, cfg *config.Config, o *options, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: frameo pair <code>")
	}
	g, err := dialGrid(ctx, cfg, o)
	if err != nil {
		return err
	}
	defer g.Close()

	peer, err := g.Pair(ctx, args[0])
	if err != nil {
		if errors.Is(err, sdg.ErrRefused) {
			return errors.New("the grid did not recognise that code: check it is current, since codes expire")
		}
		if errors.Is(err, sdg.ErrPairingFailed) {
			return errors.New("that code was not accepted: check the digits and try again")
		}
		return err
	}
	name, err := cfg.AddFrame(o.frame, peer)
	if err != nil {
		return err
	}
	fmt.Fprintf(o.out, "Paired with %s.\n", name)
	fmt.Fprintf(o.out, "Its address is %s, saved in %s.\n", peer, cfg.Path())
	return nil
}

func cmdInfo(ctx context.Context, cfg *config.Config, o *options) error {
	c, name, err := connect(ctx, cfg, o)
	if err != nil {
		return err
	}
	defer c.Close()

	info, err := c.GetInfo(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(o.out, "%s\n", name)
	fmt.Fprintf(o.out, "  Name        %s\n", info.GetName())
	if p := info.GetPlacement(); p != "" {
		fmt.Fprintf(o.out, "  Placement   %s\n", p)
	}
	fmt.Fprintf(o.out, "  Screen      %d by %d\n", info.GetScreenWidth(), info.GetScreenHeight())
	fmt.Fprintf(o.out, "  May view    %t\n", info.GetHasPermissionViewPhotos())
	fmt.Fprintf(o.out, "  May manage  %t\n", info.GetHasPermissionManagePhotos())
	if cap := info.GetFrameCapabilities(); cap != nil && cap.GetMaxVideoWidth() > 0 {
		fmt.Fprintf(o.out, "  Max video   %d by %d\n", cap.GetMaxVideoWidth(), cap.GetMaxVideoHeight())
	}
	return nil
}

func cmdSend(ctx context.Context, cfg *config.Config, o *options, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: frameo send <file|url>...")
	}
	// Every argument becomes a readable file before anything is connected to,
	// so an unreadable file or a URL that does not answer is reported without
	// a round trip rather than part way through a batch.
	sources, cleanup, err := resolveSources(ctx, args)
	defer cleanup()
	if err != nil {
		return err
	}

	c, name, err := connect(ctx, cfg, o)
	if err != nil {
		return err
	}
	defer c.Close()

	for _, s := range sources {
		id, err := c.SendPhoto(ctx, frameo.Photo{
			Path:          s.path,
			Extension:     s.extension,
			Taken:         s.taken,
			Caption:       o.caption,
			Fit:           o.fit,
			SingleSegment: o.singleSegment,
		})
		if err != nil {
			return fmt.Errorf("sending %s: %w", s.name, err)
		}
		fmt.Fprintf(o.out, "Sent %s to %s as %d.\n", s.name, name, id)
	}
	return nil
}

func cmdList(ctx context.Context, cfg *config.Config, o *options) error {
	c, name, err := connect(ctx, cfg, o)
	if err != nil {
		return err
	}
	defer c.Close()

	items, err := c.ListMedia(ctx)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		fmt.Fprintf(o.out, "%s holds no photos.\n", name)
		return nil
	}
	fmt.Fprintf(o.out, "%s holds %d item(s).\n", name, len(items))
	for _, m := range items {
		when := time.UnixMilli(m.GetCaptureDate()).UTC().Format("2006-01-02")
		shown := "hidden"
		if m.GetIsVisible() {
			shown = "shown"
		}
		fmt.Fprintf(o.out, "  %-12d %s  %s\n", m.GetMediaId(), when, shown)
	}
	return nil
}

// cmdGet copies photos off the frame. A photo that cannot be fetched is
// reported and the run carries on: the others are still worth having, and a
// listing naming a photo that has since been removed is an ordinary thing to
// meet. The exit status still says something went wrong.
func cmdGet(ctx context.Context, cfg *config.Config, o *options, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: frameo get <id>... | frameo get all")
	}
	all := len(args) == 1 && args[0] == "all"
	var ids []int64
	if !all {
		var err error
		if ids, err = parseIDs(args); err != nil {
			return err
		}
	}
	// Settle where the photos will go before opening a connection, so an
	// unusable -out costs nothing to discover.
	dir, file, err := getTarget(o.outPath, all || len(ids) > 1)
	if err != nil {
		return err
	}

	c, name, err := connect(ctx, cfg, o)
	if err != nil {
		return err
	}
	defer c.Close()

	if all {
		items, err := c.ListMedia(ctx)
		if err != nil {
			return err
		}
		for _, m := range items {
			ids = append(ids, m.GetMediaId())
		}
		if len(ids) == 0 {
			fmt.Fprintf(o.out, "%s holds no photos.\n", name)
			return nil
		}
	}

	var failed int
	for _, id := range ids {
		d, err := c.GetMedia(ctx, frameo.Fetch{
			ID:      id,
			Bound:   int32(o.size),
			Timeout: o.wait,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "frameo: photo %d: %v\n", id, err)
			failed++
			continue
		}
		path := file
		if path == "" {
			path = filepath.Join(dir, photoFileName(id, d.Media.GetCaptureDate(), d.Extension()))
		}
		// A file that cannot be written is reported like a photo that cannot be
		// fetched, for the same reason: the rest of the batch is still worth
		// having, and the count at the end says how much was lost.
		if err := writeWhole(path, d.Data); err != nil {
			fmt.Fprintf(os.Stderr, "frameo: photo %d: %v\n", id, err)
			failed++
			continue
		}
		fmt.Fprintf(o.out, "Saved %s from %s, %d bytes.\n", path, name, len(d.Data))
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d photo(s) could not be fetched", failed, len(ids))
	}
	return nil
}

// photoFileName is what one photo is saved as: when it was taken, then the
// frame's own id for it, then the format.
//
// The date leads so that a directory of photos sorts into the order they were
// taken, which is the order anyone looking through them wants. It is in UTC,
// matching what `frameo list` prints, so one photo reads the same in both
// places. The id stays because it is what every other command takes -- delete,
// hide and show all name a photo by it -- so a file can be acted on without
// going back to the listing for its number.
//
// A frame that reports no capture date leaves the photo named by its id alone.
// A date of zero would say 1970 and mean nothing.
func photoFileName(id, captureDate int64, ext string) string {
	name := strconv.FormatInt(id, 10)
	// The frame files photos under its own identifiers, which the protocol
	// allows to be negative, and a file whose name begins with a dash is read
	// as an option by most of the tools that would go on to handle it. Only
	// reachable when there is no date in front, but that is exactly the case
	// this falls back to.
	if rest, negative := strings.CutPrefix(name, "-"); negative {
		name = "n" + rest
	}
	if captureDate > 0 {
		name = time.UnixMilli(captureDate).UTC().Format("2006-01-02_150405") + "_" + name
	}
	return name + "." + ext
}

// getTarget works out where the photos go. One photo may be named directly;
// a batch cannot all be the same file, so -out has to be a directory then.
func getTarget(out string, batch bool) (dir, file string, err error) {
	if out == "" {
		return ".", "", nil
	}
	if batch {
		if err := os.MkdirAll(out, 0o755); err != nil {
			return "", "", err
		}
		return out, "", nil
	}
	// A single photo written into an existing directory keeps its own name
	// there, which is what naming a directory is asking for.
	if st, err := os.Stat(out); err == nil && st.IsDir() {
		return out, "", nil
	}
	if d := filepath.Dir(out); d != "" {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return "", "", err
		}
	}
	return "", out, nil
}

// writeWhole writes the photo, and writes it whole or not at all: an
// interrupted run must not leave a truncated file under a name that looks
// finished.
func writeWhole(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".frameo-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// cmdSetVisible hides or shows photos, which is the reversible alternative to
// deleting them: the frame keeps the photo and stops displaying it.
func cmdSetVisible(ctx context.Context, cfg *config.Config, o *options, args []string, visible bool) error {
	verb := "hide"
	if visible {
		verb = "show"
	}
	if len(args) == 0 {
		return fmt.Errorf("usage: frameo %s <id>...", verb)
	}
	ids, err := parseIDs(args)
	if err != nil {
		return err
	}

	c, name, err := connect(ctx, cfg, o)
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.SetMediaVisible(ctx, ids, visible); err != nil {
		return err
	}
	shown := "Hid"
	if visible {
		shown = "Showed"
	}
	fmt.Fprintf(o.out, "%s %d item(s) on %s.\n", shown, len(ids), name)
	return nil
}

func parseIDs(args []string) ([]int64, error) {
	ids := make([]int64, 0, len(args))
	for _, a := range args {
		id, err := strconv.ParseInt(a, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%q is not a photo id", a)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func cmdDelete(ctx context.Context, cfg *config.Config, o *options, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: frameo delete <id>...")
	}
	ids, err := parseIDs(args)
	if err != nil {
		return err
	}

	c, name, err := connect(ctx, cfg, o)
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.DeleteMedia(ctx, ids); err != nil {
		return err
	}
	fmt.Fprintf(o.out, "Removed %d item(s) from %s.\n", len(ids), name)
	return nil
}

func cmdFrames(cfg *config.Config, o *options) error {
	names := cfg.Names()
	if len(names) == 0 {
		fmt.Fprintln(o.out, "No frames are paired yet.")
		return nil
	}
	for _, n := range names {
		marker := " "
		if n == cfg.DefaultFrame {
			marker = "*"
		}
		f := cfg.Frames[n]
		fmt.Fprintf(o.out, "%s %-12s %s  paired %s\n", marker, n, f.PeerID, f.PairedAt.Format("2006-01-02"))
	}
	return nil
}

func cmdForget(cfg *config.Config, o *options, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: frameo forget <name>")
	}
	if err := cfg.RemoveFrame(args[0]); err != nil {
		return err
	}
	fmt.Fprintf(o.out, "Forgot %s. The frame still lists this client until it is removed there too.\n", args[0])
	return nil
}

func cmdWhoami(cfg *config.Config, o *options) error {
	id, err := cfg.Identity()
	if err != nil {
		return err
	}
	fmt.Fprintf(o.out, "Address  %s\n", id.Public)
	fmt.Fprintf(o.out, "Config   %s\n", cfg.Path())
	return nil
}

// cmdRaw sends an arbitrary message and prints whatever comes back. It exists
// to identify the message numbers that are not known yet: send a candidate and
// see whether the frame answers.
func cmdRaw(ctx context.Context, cfg *config.Config, o *options, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: frameo raw <number>")
	}
	n, err := strconv.ParseInt(args[0], 10, 32)
	if err != nil {
		return fmt.Errorf("%q is not a message number", args[0])
	}

	c, name, err := connect(ctx, cfg, o)
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.SendRaw(ctx, int32(n), nil); err != nil {
		return err
	}
	fmt.Fprintf(o.out, "Sent message %d to %s. Listening for replies until the timeout.\n", n, name)
	for {
		select {
		case f, ok := <-c.Frames():
			if !ok {
				return nil
			}
			fmt.Fprintf(o.out, "  reply: %s\n", f)
		case <-ctx.Done():
			return nil
		}
	}
}
