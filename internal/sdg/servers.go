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

// FrameoServers is the San Francisco grid group used by the Frameo app, as
// extracted from its MdgConfiguration. Hostnames come first because the IPv4
// literals recorded during reverse engineering no longer match what DNS
// returns; they are kept as a fallback for hosts without working IPv6.
//
// Other regional groups (Frankfurt, Singapore, New York, Hong Kong) exist and
// resolve the same way; the grid relays between them, so any group works.
var FrameoServers = []Endpoint{
	{Host: "sdgframeosfo01.frameo.net", Port: 443},
	{Host: "sdgframeosfo02.frameo.net", Port: 443},
	{Host: "138.68.252.201", Port: 443},
	{Host: "198.199.110.111", Port: 443},
}

// Other regional grid servers, found by following the naming pattern and
// confirmed to present the key below. Round trips measured from Sweden:
//
//	sdgframeolon01.frameo.net    32 ms
//	sdgframeonyc01/02.frameo.net    104 ms
//	sdgframeosfo01/02.frameo.net    168 ms
//	sdgframeosgp01/02.frameo.net    187 ms
//
// FrameoServers deliberately still lists only the San Francisco pair, because
// choosing between regions is a change to how Dial picks a server rather than
// a longer list: adding these without that would make the choice random and
// leave most connections slower than they need to be.

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
