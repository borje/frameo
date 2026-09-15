// SPDX-License-Identifier: GPL-3.0-or-later

// Package mdns browses for DNS-SD services on the local network, which is how
// a Frameo frame is found for a direct connection.
//
// It is deliberately small: it asks one question, collects the answers for as
// long as the caller allows, and stops. There is no cache, no responder and no
// continuous monitoring, because a command line tool needs none of that.
//
// Queries go out over IPv4 multicast only. A responder that answers over IPv4
// is free to advertise IPv6 addresses, and those are reported, but a device
// reachable over IPv6 alone will not be found.
package mdns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
)

// ErrNotFound means no service matching the request answered in time.
var ErrNotFound = errors.New("mdns: no matching service answered")

// Port and group are where every mDNS query and response goes.
const port = 5353

var group = net.IPv4(224, 0, 0, 251)

// Service is one discovered instance.
type Service struct {
	// Instance is the instance label, with the service type stripped: for a
	// frame this is its peer id, truncated to the 63 bytes a DNS label holds.
	Instance string
	// Host is the target name the instance resolves to, as advertised.
	Host string
	// Port is the TCP port the instance listens on.
	Port int
	// Addrs are the addresses advertised for Host, best first: IPv4 before
	// IPv6, and routable addresses before link-local ones. When a responder
	// advertises no address at all, this holds the address it answered from.
	Addrs []netip.Addr
	// From is the address the answer came from, which is not always one of
	// Addrs: a responder may advertise addresses it is not answering on.
	From netip.Addr
}

// Addr is the address to connect to, and reports false when none was learnt.
func (s Service) Addr() (netip.Addr, bool) {
	if len(s.Addrs) == 0 {
		return netip.Addr{}, false
	}
	return s.Addrs[0], true
}

func (s Service) String() string {
	addr := s.Host
	if a, ok := s.Addr(); ok {
		addr = a.String()
	}
	return fmt.Sprintf("%s at %s", s.Instance, net.JoinHostPort(addr, strconv.Itoa(s.Port)))
}

// Options tunes a browse. The zero value is usable.
type Options struct {
	// Interfaces are the network interfaces to query on. Empty means every
	// interface that is up, supports multicast and has an IPv4 address.
	Interfaces []net.Interface
	// Retry is how often to repeat the query, since a multicast query or its
	// answer can be lost with nothing to notice. Defaults to 900ms.
	Retry time.Duration
	// Logger receives tracing. Nil discards it.
	Logger *slog.Logger
}

func (o *Options) withDefaults() *Options {
	c := &Options{}
	if o != nil {
		*c = *o
	}
	if c.Retry <= 0 {
		c.Retry = 900 * time.Millisecond
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return c
}

// Browse collects every instance of a service type that answers before ctx is
// done. Because there is no way to know that every device has answered, it
// always runs until ctx ends: give it a deadline, and expect to wait for it.
func Browse(ctx context.Context, service string, opt *Options) ([]Service, error) {
	var found []Service
	err := browse(ctx, service, opt, func(s Service) bool {
		found = append(found, s)
		return false
	})
	// Running out of time is how a browse ends, not a failure.
	if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		return found, err
	}
	return found, nil
}

// Lookup returns the first instance of a service type whose name is accepted
// by want. Unlike Browse it stops as soon as one matches, so it costs a round
// trip rather than a full window when the device is there.
func Lookup(ctx context.Context, service string, want func(instance string) bool, opt *Options) (Service, error) {
	var found Service
	var ok bool
	err := browse(ctx, service, opt, func(s Service) bool {
		if !want(s.Instance) {
			return false
		}
		found, ok = s, true
		return true
	})
	if ok {
		return found, nil
	}
	return Service{}, lookupErr(ctx, err)
}

// lookupErr says what a browse that matched nothing means. The window running
// out is what ErrNotFound is for; the caller giving up is not, since a lookup
// cut short by Ctrl-C has learnt nothing about whether the frame is here and
// reporting an absence would blame the network for the interruption.
func lookupErr(ctx context.Context, err error) error {
	if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		return err
	}
	if err := ctx.Err(); errors.Is(err, context.Canceled) {
		return err
	}
	return ErrNotFound
}

// packet is one response as it arrived.
type packet struct {
	data []byte
	from netip.Addr
}

// browse runs one query until emit says to stop or ctx ends. emit is called
// once per instance, in the order the instances complete.
func browse(ctx context.Context, service string, opt *Options, emit func(Service) bool) error {
	o := opt.withDefaults()

	fqdn := serviceFQDN(service)
	query, err := buildQuery(fqdn)
	if err != nil {
		return err
	}

	ifis, err := usableInterfaces(o.Interfaces)
	if err != nil {
		return err
	}

	packets := make(chan packet, 16)
	var conns []*net.UDPConn
	for _, ifi := range ifis {
		c, err := net.ListenMulticastUDP("udp4", &ifi, &net.UDPAddr{IP: group, Port: port})
		if err != nil {
			// One unusable interface is ordinary: a container bridge with no
			// multicast route, an interface that went down as we looked.
			o.Logger.Debug("mdns: interface unusable", "interface", ifi.Name, "err", err)
			continue
		}
		if err := ipv4.NewPacketConn(c).SetMulticastInterface(&ifi); err != nil {
			o.Logger.Debug("mdns: cannot aim multicast", "interface", ifi.Name, "err", err)
		}
		conns = append(conns, c)
		go readInto(c, packets)
	}
	if len(conns) == 0 {
		return errors.New("mdns: no network interface could be used for discovery")
	}
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()

	send := func() {
		to := &net.UDPAddr{IP: group, Port: port}
		for _, c := range conns {
			if _, err := c.WriteToUDP(query, to); err != nil {
				o.Logger.Debug("mdns: query not sent", "local", c.LocalAddr(), "err", err)
			}
		}
	}
	send()

	retry := time.NewTicker(o.Retry)
	defer retry.Stop()

	col := newCollector(fqdn)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-retry.C:
			send()
		case p := <-packets:
			for _, s := range col.absorb(p, o.Logger) {
				o.Logger.Debug("mdns: found", "service", s.String())
				if emit(s) {
					return nil
				}
			}
		}
	}
}

// readInto forwards every datagram to packets until the connection is closed.
func readInto(c *net.UDPConn, packets chan<- packet) {
	// Responses carrying many records are large; 9000 covers anything that
	// fits a jumbo frame, which is more than a responder will send.
	buf := make([]byte, 9000)
	for {
		n, src, err := c.ReadFromUDP(buf)
		if err != nil {
			return
		}
		from, _ := netip.AddrFromSlice(src.IP)
		data := make([]byte, n)
		copy(data, buf[:n])
		select {
		case packets <- packet{data: data, from: from.Unmap()}:
		default: // A slow consumer drops packets rather than blocking the read.
		}
	}
}

// usableInterfaces returns the interfaces to query on, either the ones asked
// for or every one that could carry a multicast query.
func usableInterfaces(want []net.Interface) ([]net.Interface, error) {
	if len(want) > 0 {
		return want, nil
	}
	all, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("mdns: listing interfaces: %w", err)
	}
	var out []net.Interface
	for _, ifi := range all {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if !hasIPv4(ifi) {
			continue
		}
		out = append(out, ifi)
	}
	if len(out) == 0 {
		return nil, errors.New("mdns: no interface is up with an IPv4 address and multicast")
	}
	return out, nil
}

func hasIPv4(ifi net.Interface) bool {
	addrs, err := ifi.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
			return true
		}
	}
	return false
}

// serviceFQDN turns a service type into the name to ask about, accepting it
// with or without the trailing local domain.
func serviceFQDN(service string) string {
	name := strings.TrimSuffix(service, ".")
	if !strings.HasSuffix(name, ".local") {
		name += ".local"
	}
	return name + "."
}

// buildQuery encodes one PTR question for the service type. The response is
// asked for over multicast, the way a browsing client asks, so that responders
// which ignore requests for a unicast answer still reply.
func buildQuery(fqdn string) ([]byte, error) {
	name, err := dnsmessage.NewName(fqdn)
	if err != nil {
		return nil, fmt.Errorf("mdns: %q is not a usable service name: %w", fqdn, err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{
		Name:  name,
		Type:  dnsmessage.TypePTR,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		return nil, err
	}
	return b.Finish()
}
