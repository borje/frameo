// SPDX-License-Identifier: GPL-3.0-or-later

package sdg

import (
	"net"
	"strconv"
)

// Endpoint is one grid server to try.
type Endpoint struct {
	Host string
	Port int
}

// String renders the endpoint as a dial address, bracketing a bare IPv6
// literal so it is not mistaken for a host and port.
func (e Endpoint) String() string { return net.JoinHostPort(e.Host, strconv.Itoa(e.Port)) }

// FrameoServers is every regional grid group confirmed to present
// FrameoServerKey: San Francisco, from the Frameo app's own
// MdgConfiguration, plus London, New York and Singapore, found by following
// its naming pattern. Dial races all of them and keeps whichever answers
// first, so listing every known region here lets the nearest one win instead
// of guessing at one in advance. Round trips measured from Sweden:
//
//	sdgframeolon01.frameo.net       32 ms
//	sdgframeonyc01/02.frameo.net   104 ms
//	sdgframeosfo01/02.frameo.net   168 ms
//	sdgframeosgp01/02.frameo.net   187 ms
//
// Other regional groups (Frankfurt, Hong Kong) are known to exist and resolve
// the same way, but no hostname for either has been confirmed yet; the grid
// relays between every group, so any of them works.
//
// Hostnames come first within each group because the IPv4 literals recorded
// during reverse engineering no longer match what DNS returns for San
// Francisco; they are kept as a fallback for hosts without working IPv6.
var FrameoServers = []Endpoint{
	{Host: "sdgframeolon01.frameo.net", Port: 443},
	{Host: "sdgframeonyc01.frameo.net", Port: 443},
	{Host: "sdgframeonyc02.frameo.net", Port: 443},
	{Host: "sdgframeosfo01.frameo.net", Port: 443},
	{Host: "sdgframeosfo02.frameo.net", Port: 443},
	{Host: "sdgframeosgp01.frameo.net", Port: 443},
	{Host: "sdgframeosgp02.frameo.net", Port: 443},
	{Host: "138.68.252.201", Port: 443},
	{Host: "198.199.110.111", Port: 443},
}

// FrameoServerKey is the long-term public key of the Frameo grid servers. The
// app ships this value as the one server certificate it will accept, and a
// live connection confirms the grid presents exactly it. Pinning it means a
// grid server cannot be impersonated by whoever controls the name resolution.
var FrameoServerKey = mustKey("579b1d8476a9fcdef9a3acdea4d3ddd91d9f9c228762a1c08a5b45cff933f015")

func mustKey(s string) Key {
	k, err := ParseKey(s)
	if err != nil {
		panic(err)
	}
	return k
}

// DanfossServers is the well-known DEVISmart grid, useful for checking the
// transport against a second, independent SDG deployment.
var DanfossServers = []Endpoint{
	{Host: "77.66.11.90", Port: 443},
	{Host: "77.66.11.92", Port: 443},
	{Host: "5.179.92.180", Port: 443},
	{Host: "5.179.92.182", Port: 443},
}
