// Package discovery turns raw link-layer discovery frames into a single tidy
// Neighbor record, so callers do not have to care whether the switch on the
// other end of the cable speaks LLDP or CDP.
//
// LLDP (IEEE 802.1AB) frames are Ethernet frames with ethertype 0x88CC sent to
// the multicast MAC 01:80:c2:00:00:0e. CDP (Cisco proprietary) frames are
// 802.3/LLC-SNAP frames sent to 01:00:0c:cc:cc:cc. Both are emitted roughly
// every 30s and are consumed by the first switch that sees them, so a listener
// has to sit on the wire for at least one advertisement interval.
//
// Plenty of access ports run one protocol and not the other, which is why
// walljack listens for both.
package discovery

import (
	"github.com/google/gopacket"
)

// BPFFilter matches both discovery protocols in one capture filter: LLDP by
// its ethertype, and CDP by its destination multicast (CDP rides inside
// LLC/SNAP, so it has no ethertype of its own to match on).
//
// The Cisco multicast address is shared with VTP, DTP, PAgP and UDLD, so some
// frames that pass this filter will not be CDP. Parse simply ignores them.
const BPFFilter = "ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc"

// Protocol names the discovery protocol a Neighbor was learned from.
type Protocol string

const (
	ProtocolLLDP Protocol = "LLDP"
	ProtocolCDP  Protocol = "CDP"
)

// Neighbor is the flattened, human-facing view of a single advertisement.
//
// Not every field is carried by every protocol, and even within one protocol
// most fields are optional, so expect blanks. The two that are effectively
// always present are ChassisID and PortID.
type Neighbor struct {
	Protocol        Protocol
	ChassisID       string // LLDP: Chassis ID TLV. CDP: Device ID (usually the hostname).
	PortID          string
	PortDescription string
	SystemName      string
	SystemDescr     string
	Platform        string // CDP only: the hardware model string.
	VLAN            string
	ManagementIP    string
}

// Key identifies a neighbour for de-duplication. Chassis plus port is enough:
// one physical switch port only ever advertises itself once per interval.
func (n Neighbor) Key() string {
	return string(n.Protocol) + "|" + n.ChassisID + "|" + n.PortID
}

// ChassisLabel returns the right human name for the chassis field, which the
// two protocols think about differently: LLDP identifies the chassis (often a
// MAC address), CDP identifies the device (usually its hostname).
func (n Neighbor) ChassisLabel() string {
	if n.Protocol == ProtocolCDP {
		return "Device ID"
	}
	return "Chassis ID"
}

// Parse extracts a Neighbor from a packet, trying each supported protocol in
// turn. It returns false if the packet carries neither.
func Parse(packet gopacket.Packet) (Neighbor, bool) {
	if n, ok := parseLLDP(packet); ok {
		return n, true
	}
	if n, ok := parseCDP(packet); ok {
		return n, true
	}
	return Neighbor{}, false
}
