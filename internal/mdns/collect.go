// SPDX-License-Identifier: GPL-3.0-or-later

package mdns

import (
	"log/slog"
	"net/netip"
	"sort"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// collector assembles services out of the records that arrive. A responder
// normally sends the PTR, SRV and address records for an instance in one
// packet, but nothing requires it to, so records are kept until an instance
// has what it needs.
type collector struct {
	service string // the service type asked about, as a fully qualified name

	instances map[string]*instance    // by instance name, fully qualified
	addrs     map[string][]netip.Addr // by host name, fully qualified
	emitted   map[string]bool
}

type instance struct {
	host string
	port int
	from netip.Addr
}

func newCollector(service string) *collector {
	return &collector{
		service:   strings.ToLower(service),
		instances: map[string]*instance{},
		addrs:     map[string][]netip.Addr{},
		emitted:   map[string]bool{},
	}
}

// absorb reads one response and returns the services it completed. An instance
// is reported once: later records that add an address to an instance already
// reported are kept but change nothing, since the caller has already been
// given somewhere to connect.
func (c *collector) absorb(p packet, log *slog.Logger) []Service {
	var msg dnsmessage.Message
	if err := msg.Unpack(p.data); err != nil {
		log.Debug("mdns: unreadable response", "from", p.from, "err", err)
		return nil
	}
	// Only a response advertises anything. Another machine browsing this
	// service puts the instances it already knows of into its query as known
	// answers (RFC 6762 7.1), and we are in the group, so we see them: taking
	// those for advertisements would file the querier's address as the
	// device's.
	if !msg.Header.Response {
		return nil
	}

	for _, section := range [][]dnsmessage.Resource{msg.Answers, msg.Authorities, msg.Additionals} {
		for _, r := range section {
			c.record(r, p.from)
		}
	}

	var out []Service
	for name, inst := range c.instances {
		if c.emitted[name] || inst.host == "" {
			continue
		}
		c.emitted[name] = true
		out = append(out, c.build(name, inst))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Instance < out[j].Instance })
	return out
}

// record files one resource record under the name it describes.
func (c *collector) record(r dnsmessage.Resource, from netip.Addr) {
	name := strings.ToLower(r.Header.Name.String())
	switch body := r.Body.(type) {
	case *dnsmessage.PTRResource:
		// Only the service type we asked about; a responder answering a
		// browse often volunteers others.
		if name != c.service {
			return
		}
		c.instanceFor(strings.ToLower(body.PTR.String()), from)

	case *dnsmessage.SRVResource:
		if !c.isInstance(name) {
			return
		}
		inst := c.instanceFor(name, from)
		inst.host = strings.ToLower(body.Target.String())
		inst.port = int(body.Port)
		// The SRV is the record that describes the service, so whoever sent it
		// is the address to fall back on: an instance first heard of in
		// another responder's packet would otherwise keep that packet's
		// address.
		inst.from = from

	case *dnsmessage.AResource:
		c.addrs[name] = appendAddr(c.addrs[name], netip.AddrFrom4(body.A))

	case *dnsmessage.AAAAResource:
		c.addrs[name] = appendAddr(c.addrs[name], netip.AddrFrom16(body.AAAA))
	}
}

// isInstance reports whether a name is an instance of the service asked about.
func (c *collector) isInstance(name string) bool {
	return strings.HasSuffix(name, "."+c.service) && len(name) > len(c.service)+1
}

func (c *collector) instanceFor(name string, from netip.Addr) *instance {
	if inst, ok := c.instances[name]; ok {
		return inst
	}
	inst := &instance{from: from}
	c.instances[name] = inst
	return inst
}

// build assembles the reported form of one instance.
func (c *collector) build(name string, inst *instance) Service {
	addrs := c.addrs[inst.host]
	if len(addrs) == 0 && inst.from.IsValid() {
		// A responder that advertises no address still answered from one, and
		// that address is the device.
		addrs = []netip.Addr{inst.from}
	}
	sorted := make([]netip.Addr, len(addrs))
	copy(sorted, addrs)
	sort.SliceStable(sorted, func(i, j int) bool { return addrRank(sorted[i]) < addrRank(sorted[j]) })

	return Service{
		Instance: strings.TrimSuffix(name, "."+c.service),
		Host:     strings.TrimSuffix(inst.host, "."),
		Port:     inst.port,
		Addrs:    sorted,
		From:     inst.from,
	}
}

// addrRank orders addresses by how likely they are to work: IPv4 first,
// because that is the family the query went out over, then IPv6, with
// link-local addresses last in either family -- an IPv6 one needs a zone this
// package does not carry, and an IPv4 one (169.254.0.0/16) is what a device
// gives itself when DHCP failed, so it is the address least likely to be the
// one that answered. Link-local is therefore tested first, before the family,
// or every IPv4 address would rank alike.
func addrRank(a netip.Addr) int {
	switch {
	case a.IsLinkLocalUnicast():
		return 2
	case a.Is4() || a.Is4In6():
		return 0
	default:
		return 1
	}
}

func appendAddr(list []netip.Addr, a netip.Addr) []netip.Addr {
	a = a.Unmap()
	for _, have := range list {
		if have == a {
			return list
		}
	}
	return append(list, a)
}
