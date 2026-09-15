// SPDX-License-Identifier: GPL-3.0-or-later

package mdns

import (
	"log/slog"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

const frameoService = "_frameo._tcp.local."

// response builds a packet the way a responder does, with the answer section
// carrying whatever records are given.
func response(t *testing.T, records ...dnsmessage.Resource) []byte {
	t.Helper()
	msg := dnsmessage.Message{
		Header:  dnsmessage.Header{Response: true, Authoritative: true},
		Answers: records,
	}
	b, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func name(t *testing.T, s string) dnsmessage.Name {
	t.Helper()
	n, err := dnsmessage.NewName(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func ptr(t *testing.T, owner, target string) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: name(t, owner), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.PTRResource{PTR: name(t, target)},
	}
}

func srv(t *testing.T, owner, target string, port uint16) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: name(t, owner), Type: dnsmessage.TypeSRV, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.SRVResource{Target: name(t, target), Port: port},
	}
}

func a(t *testing.T, owner string, addr [4]byte) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: name(t, owner), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.AResource{A: addr},
	}
}

func aaaa(t *testing.T, owner string, addr [16]byte) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: name(t, owner), Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.AAAAResource{AAAA: addr},
	}
}

func absorb(t *testing.T, c *collector, data []byte, from string) []Service {
	t.Helper()
	return c.absorb(packet{data: data, from: netip.MustParseAddr(from)}, slog.Default())
}

// TestCollectOneAnswer covers the shape a frame actually sends: every record
// for the instance in one packet.
func TestCollectOneAnswer(t *testing.T) {
	const instance = "f77db3505d636efcf03d6b89e7eabb757eb7a781cb284c131e9468f96a53fa4"
	c := newCollector(frameoService)

	got := absorb(t, c, response(t,
		ptr(t, frameoService, instance+"."+frameoService),
		srv(t, instance+"."+frameoService, "android-2.local.", 60027),
		a(t, "android-2.local.", [4]byte{192, 168, 1, 135}),
		aaaa(t, "android-2.local.", netip.MustParseAddr("fe80::6a8f:c1ff:fea8:5987").As16()),
		aaaa(t, "android-2.local.", netip.MustParseAddr("fdfa:2018:5ea8:2eb7::1").As16()),
	), "192.168.1.135")

	if len(got) != 1 {
		t.Fatalf("got %d services, want 1", len(got))
	}
	s := got[0]
	if s.Instance != instance {
		t.Errorf("instance %q", s.Instance)
	}
	if s.Host != "android-2.local" || s.Port != 60027 {
		t.Errorf("resolved to %s:%d", s.Host, s.Port)
	}
	addr, ok := s.Addr()
	if !ok || addr.String() != "192.168.1.135" {
		t.Errorf("first address is %v, want the IPv4 one", addr)
	}
	// Link-local addresses are last, since connecting to one needs a zone.
	if last := s.Addrs[len(s.Addrs)-1]; !last.IsLinkLocalUnicast() {
		t.Errorf("last address is %v, want the link-local one", last)
	}
}

// TestCollectAcrossPackets covers a responder that splits its answer, which
// nothing forbids.
func TestCollectAcrossPackets(t *testing.T) {
	const instance = "abc"
	c := newCollector(frameoService)

	if got := absorb(t, c, response(t, ptr(t, frameoService, instance+"."+frameoService)), "192.168.1.9"); len(got) != 0 {
		t.Fatalf("a PTR alone produced %d services; there is nowhere to connect yet", len(got))
	}
	got := absorb(t, c, response(t, srv(t, instance+"."+frameoService, "frame.local.", 1234)), "192.168.1.9")
	if len(got) != 1 {
		t.Fatalf("got %d services once the SRV arrived, want 1", len(got))
	}
	if addr, ok := got[0].Addr(); !ok || addr.String() != "192.168.1.9" {
		t.Errorf("address %v: with no address record, the responder's own address is the device", addr)
	}
	if again := absorb(t, c, response(t, srv(t, instance+"."+frameoService, "frame.local.", 1234)), "192.168.1.9"); len(again) != 0 {
		t.Errorf("the same instance was reported twice")
	}
}

// TestCollectIgnoresOtherServices covers the noise on a real network: a
// responder answering a browse volunteers records for everything it has.
func TestCollectIgnoresOtherServices(t *testing.T) {
	c := newCollector(frameoService)
	got := absorb(t, c, response(t,
		ptr(t, "_sonos._tcp.local.", "Sonos-000E5880266C._sonos._tcp.local."),
		srv(t, "Sonos-000E5880266C._sonos._tcp.local.", "sonos.local.", 1443),
		a(t, "sonos.local.", [4]byte{192, 168, 1, 223}),
	), "192.168.1.223")
	if len(got) != 0 {
		t.Fatalf("another service was reported as a frame: %v", got)
	}
}

func TestServiceFQDN(t *testing.T) {
	for _, in := range []string{"_frameo._tcp", "_frameo._tcp.", "_frameo._tcp.local", "_frameo._tcp.local."} {
		if got := serviceFQDN(in); got != frameoService {
			t.Errorf("serviceFQDN(%q) = %q", in, got)
		}
	}
}

func TestBuildQueryIsAPTRQuestion(t *testing.T) {
	q, err := buildQuery(frameoService)
	if err != nil {
		t.Fatal(err)
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(q); err != nil {
		t.Fatalf("our own query does not parse: %v", err)
	}
	if len(msg.Questions) != 1 {
		t.Fatalf("query carries %d questions", len(msg.Questions))
	}
	q0 := msg.Questions[0]
	if q0.Name.String() != frameoService || q0.Type != dnsmessage.TypePTR {
		t.Errorf("query asks %s %v", q0.Name.String(), q0.Type)
	}
	// The unicast-response bit lives in the top bit of the class. Leaving it
	// clear is what makes responders that ignore it answer anyway.
	if q0.Class != dnsmessage.ClassINET {
		t.Errorf("query class is %v, want a plain multicast question", q0.Class)
	}
}

// query builds a packet the way another machine browsing this service does:
// a question, carrying the instances it already knows of as known answers.
func query(t *testing.T, records ...dnsmessage.Resource) []byte {
	t.Helper()
	msg := dnsmessage.Message{
		Questions: []dnsmessage.Question{{
			Name:  name(t, frameoService),
			Type:  dnsmessage.TypePTR,
			Class: dnsmessage.ClassINET,
		}},
		Answers: records,
	}
	b, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestCollectIgnoresAnotherBrowsersQuery covers the packet that would
// otherwise hand back the wrong machine's address. A neighbour browsing this
// same service lists what it already knows as known answers, and we are in the
// group, so its query arrives here looking much like an advertisement.
func TestCollectIgnoresAnotherBrowsersQuery(t *testing.T) {
	const instance = "abc"
	c := newCollector(frameoService)

	if got := absorb(t, c, query(t,
		ptr(t, frameoService, instance+"."+frameoService),
		srv(t, instance+"."+frameoService, "frame.local.", 1234),
	), "192.168.1.50"); len(got) != 0 {
		t.Fatalf("a query was taken for an advertisement: %v", got)
	}

	got := absorb(t, c, response(t,
		ptr(t, frameoService, instance+"."+frameoService),
		srv(t, instance+"."+frameoService, "frame.local.", 1234),
	), "192.168.1.9")
	if len(got) != 1 {
		t.Fatalf("got %d services once the frame itself answered, want 1", len(got))
	}
	if addr, ok := got[0].Addr(); !ok || addr.String() != "192.168.1.9" {
		t.Errorf("address %v, want the address the frame answered from", addr)
	}
}

// TestCollectFallsBackToTheSRVSender covers an instance mentioned by more than
// one responder: the address to fall back on is the one that described the
// service, not the one that happened to mention it first.
func TestCollectFallsBackToTheSRVSender(t *testing.T) {
	const instance = "abc"
	c := newCollector(frameoService)

	if got := absorb(t, c, response(t, ptr(t, frameoService, instance+"."+frameoService)), "192.168.1.50"); len(got) != 0 {
		t.Fatalf("a PTR alone produced %d services", len(got))
	}
	got := absorb(t, c, response(t, srv(t, instance+"."+frameoService, "frame.local.", 1234)), "192.168.1.9")
	if len(got) != 1 {
		t.Fatalf("got %d services once the SRV arrived, want 1", len(got))
	}
	if addr, ok := got[0].Addr(); !ok || addr.String() != "192.168.1.9" {
		t.Errorf("address %v, want the sender of the SRV rather than of the PTR", addr)
	}
}

// TestCollectRanksSelfAssignedAddressesLast covers a frame whose DHCP failed:
// it advertises a 169.254 address of its own making alongside a routable one,
// and dialling the wrong one first costs the whole connect budget before the
// relay is tried.
func TestCollectRanksSelfAssignedAddressesLast(t *testing.T) {
	const instance = "abc"
	c := newCollector(frameoService)

	got := absorb(t, c, response(t,
		ptr(t, frameoService, instance+"."+frameoService),
		srv(t, instance+"."+frameoService, "frame.local.", 1234),
		// Advertised before the routable address, so order alone would pick it.
		a(t, "frame.local.", [4]byte{169, 254, 8, 3}),
		a(t, "frame.local.", [4]byte{192, 168, 1, 135}),
	), "192.168.1.135")

	if len(got) != 1 {
		t.Fatalf("got %d services, want 1", len(got))
	}
	addr, ok := got[0].Addr()
	if !ok || addr.String() != "192.168.1.135" {
		t.Errorf("first address is %v, want the routable one", addr)
	}
	if last := got[0].Addrs[len(got[0].Addrs)-1]; last.String() != "169.254.8.3" {
		t.Errorf("last address is %v, want the self-assigned one", last)
	}
}
