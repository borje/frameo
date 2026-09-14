package sdg

import "strconv"

// Endpoint is one grid server to try.
type Endpoint struct {
	Host string
	Port int
}

func (e Endpoint) String() string { return e.Host + ":" + strconv.Itoa(e.Port) }

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

// DanfossServers is the well-known DEVISmart grid, useful for checking the
// transport against a second, independent SDG deployment.
var DanfossServers = []Endpoint{
	{Host: "77.66.11.90", Port: 443},
	{Host: "77.66.11.92", Port: 443},
	{Host: "5.179.92.180", Port: 443},
	{Host: "5.179.92.182", Port: 443},
}
