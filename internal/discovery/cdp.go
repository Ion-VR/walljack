package discovery

import (
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// parseCDP extracts a Neighbor from a Cisco Discovery Protocol advertisement.
//
// CDP matters here because a great many access ports, especially in older
// enterprise and hospitality estates, run CDP with LLDP switched off. An
// LLDP-only tool reports "nothing found" on those jacks, which looks like a
// broken tool rather than an absent protocol.
//
// The frame arrives as Ethernet -> LLC -> SNAP -> CiscoDiscovery ->
// CiscoDiscoveryInfo; gopacket walks that chain for us, so we only need the
// decoded info layer. Other traffic to the same Cisco multicast (VTP, DTP,
// PAgP, UDLD) has no CiscoDiscoveryInfo layer and falls through as not-CDP.
func parseCDP(packet gopacket.Packet) (Neighbor, bool) {
	info, ok := packet.Layer(layers.LayerTypeCiscoDiscoveryInfo).(*layers.CiscoDiscoveryInfo)
	if !ok || info == nil {
		return Neighbor{}, false
	}

	n := Neighbor{
		Protocol: ProtocolCDP,
		// CDP's Device ID is usually the switch hostname rather than a MAC,
		// which is friendlier than LLDP's chassis ID but occupies the same slot.
		ChassisID:   cleanString(info.DeviceID),
		PortID:      cleanString(info.PortID),
		SystemName:  cleanString(info.SysName),
		SystemDescr: cleanString(info.Version),
		Platform:    cleanString(info.Platform),
		// Management address TLV first, then the general address TLV: switches
		// differ on which one they populate.
		ManagementIP: firstIP(info.MgmtAddresses, info.Addresses),
	}

	// Most switches send only Device ID and never the newer System Name TLV.
	// Treating the device ID as the system name keeps the printed output
	// consistent between the two protocols.
	if n.SystemName == "" {
		n.SystemName = n.ChassisID
	}

	// CDP advertises the native (untagged) VLAN of the port, which is the
	// closest equivalent to LLDP's PVID.
	if info.NativeVLAN != 0 {
		n.VLAN = strconv.Itoa(int(info.NativeVLAN))
	}

	return n, true
}
