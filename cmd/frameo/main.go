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
  send <file>...     send photos
  list               list the photos on the frame
  delete <id>...     remove photos from the frame
  frames             list paired frames
  forget <name>      forget a paired frame
  whoami             print this client's own identity
  raw <number>       send an empty message with the given number and report replies

Options:
  -frame <name>      which paired frame to use (default: the first one paired)
  -caption <text>    caption to send with a photo
  -fit               fit the whole photo on screen instead of cropping to fill
  -single-segment    send each photo as one message instead of a series
  -timeout <dur>     give up after this long, covering the whole run (default 15m)
  -config <path>     configuration file (default: under the user config dir)
  -server <host:port>  use this grid server instead of Frameo's
  -type <number>     message number for list or delete, whose numbers are not
                     known yet; try 31 for list
  -v                 log the protocol exchange

The numbers list and delete need were never observed, so both refuse unless
-type supplies one. See internal/frameo/types.go for what is known.
`

type options struct {
	out           io.Writer
	frame         string
	caption       string
	fit           bool
	singleSegment bool
	timeout       time.Duration
	configPath    string
	server        string
	msgType       int
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
	fs.BoolVar(&o.fit, "fit", false, "fit the whole photo on screen")
	fs.BoolVar(&o.singleSegment, "single-segment", false, "send each photo as one message")
	fs.DurationVar(&o.timeout, "timeout", 15*time.Minute, "give up after this long")
	fs.StringVar(&o.configPath, "config", "", "configuration file")
	fs.StringVar(&o.server, "server", "", "grid server to use")
	fs.IntVar(&o.msgType, "type", 0, "message number to use for a command whose number is unknown")
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
		return errors.New("usage: frameo send <file>...")
	}
	// Fail before connecting if a file is unreadable, rather than part way
	// through a batch.
	for _, path := range args {
		if _, err := os.Stat(path); err != nil {
			return err
		}
	}

	c, name, err := connect(ctx, cfg, o)
	if err != nil {
		return err
	}
	defer c.Close()

	for _, path := range args {
		id, err := c.SendPhoto(ctx, frameo.Photo{
			Path:          path,
			Caption:       o.caption,
			Fit:           o.fit,
			SingleSegment: o.singleSegment,
		})
		if err != nil {
			return fmt.Errorf("sending %s: %w", path, err)
		}
		fmt.Fprintf(o.out, "Sent %s to %s as %d.\n", path, name, id)
	}
	return nil
}

func cmdList(ctx context.Context, cfg *config.Config, o *options) error {
	c, name, err := connect(ctx, cfg, o)
	if err != nil {
		return err
	}
	defer c.Close()

	items, err := c.ListMedia(ctx, int32(o.msgType))
	if errors.Is(err, frameo.ErrTypeUnknown) {
		return fmt.Errorf("%w\ntry: frameo -type %d list", err, frameo.CandidateGetAllMediaMetaData)
	}
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

func cmdDelete(ctx context.Context, cfg *config.Config, o *options, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: frameo delete <id>...")
	}
	ids := make([]int64, 0, len(args))
	for _, a := range args {
		id, err := strconv.ParseInt(a, 10, 64)
		if err != nil {
			return fmt.Errorf("%q is not a photo id", a)
		}
		ids = append(ids, id)
	}

	c, name, err := connect(ctx, cfg, o)
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.DeleteMedia(ctx, ids, int32(o.msgType)); err != nil {
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
