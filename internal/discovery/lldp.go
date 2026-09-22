package discovery

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// parseLLDP extracts a Neighbor from an LLDP advertisement, returning false if
// the packet does not carry the mandatory LLDP layer.
func parseLLDP(packet gopacket.Packet) (Neighbor, bool) {
	disc, ok := packet.Layer(layers.LayerTypeLinkLayerDiscovery).(*layers.LinkLayerDiscovery)
	if !ok || disc == nil {
		return Neighbor{}, false
	}

	n := Neighbor{
		Protocol:  ProtocolLLDP,
		ChassisID: formatChassisID(disc.ChassisID),
		PortID:    formatPortID(disc.PortID),
	}

	// The optional TLVs (port description, system name, VLAN, mgmt address)
	// live in a separate decoded layer. They may be absent on minimal
	// advertisements, which is common on cheaper managed switches.
	if info, ok := packet.Layer(layers.LayerTypeLinkLayerDiscoveryInfo).(*layers.LinkLayerDiscoveryInfo); ok && info != nil {
		n.PortDescription = cleanString(info.PortDescription)
		n.SystemName = cleanString(info.SysName)
		n.SystemDescr = cleanString(info.SysDescription)
		n.ManagementIP = formatMgmtAddress(info.MgmtAddress)
		n.VLAN = extractVLAN(info)
	}

	return n, true
}

// extractVLAN reads the Port VLAN ID (PVID) from the IEEE 802.1 organisationally
// specific TLV. A PVID of 0 means "not advertised" per the spec.
func extractVLAN(info *layers.LinkLayerDiscoveryInfo) string {
	d, err := info.Decode8021()
	if err != nil {
		return ""
	}
	if d.PVID != 0 {
		return fmt.Sprintf("%d", d.PVID)
	}
	// Fall back to the first named VLAN if no port VLAN was given.
	if len(d.VLANNames) > 0 {
		v := d.VLANNames[0]
		return fmt.Sprintf("%d (%s)", v.ID, cleanString(v.Name))
	}
	return ""
}
