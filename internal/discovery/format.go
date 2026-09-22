package discovery

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket/layers"
)

// padding is the set of bytes switches habitually tack onto the end of string
// TLVs. Null padding is the common one: plenty of gear sends a fixed-width
// buffer and lets the nulls ride along, which would otherwise make a perfectly
// readable system name fail the printable check and come out as hex.
const padding = "\x00 \t\r\n"

// cleanString trims the padding that vendors leave on string TLVs.
func cleanString(s string) string {
	return strings.Trim(s, padding)
}

func trimPadding(b []byte) []byte {
	return bytes.Trim(b, padding)
}

func formatChassisID(c layers.LLDPChassisID) string {
	switch c.Subtype {
	case layers.LLDPChassisIDSubTypeMACAddr:
		return formatMAC(c.ID)
	case layers.LLDPChassisIDSubTypeNetworkAddr:
		return formatNetworkAddr(c.ID)
	default:
		return printableOrHex(c.ID)
	}
}

func formatPortID(p layers.LLDPPortID) string {
	switch p.Subtype {
	case layers.LLDPPortIDSubtypeMACAddr:
		return formatMAC(p.ID)
	case layers.LLDPPortIDSubtypeNetworkAddr:
		return formatNetworkAddr(p.ID)
	default:
		return printableOrHex(p.ID)
	}
}

// formatMgmtAddress renders the management address TLV, preferring IPv4/IPv6
// presentation and falling back to hex for exotic address families.
func formatMgmtAddress(m layers.LLDPMgmtAddress) string {
	if len(m.Address) == 0 {
		return ""
	}
	switch m.Subtype {
	case layers.IANAAddressFamilyIPV4:
		if len(m.Address) == 4 {
			return net.IP(m.Address).String()
		}
	case layers.IANAAddressFamilyIPV6:
		if len(m.Address) == 16 {
			return net.IP(m.Address).String()
		}
	case layers.IANAAddressFamily802:
		return formatMAC(m.Address)
	}
	return printableOrHex(m.Address)
}

// formatNetworkAddr handles the address-family-prefixed byte slice used by the
// "network address" subtype: the first byte is an IANA address family number.
func formatNetworkAddr(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	family := layers.IANAAddressFamily(b[0])
	rest := b[1:]
	switch family {
	case layers.IANAAddressFamilyIPV4:
		if len(rest) == 4 {
			return net.IP(rest).String()
		}
	case layers.IANAAddressFamilyIPV6:
		if len(rest) == 16 {
			return net.IP(rest).String()
		}
	}
	return printableOrHex(rest)
}

func formatMAC(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, ":")
}

// printableOrHex returns the bytes as a string if they look like printable
// text, otherwise as an explicitly marked hex string. Switch identifiers are
// sometimes ASCII, sometimes not, and rendering raw bytes as colon-separated
// pairs would read as a malformed MAC address rather than as raw bytes.
func printableOrHex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	trimmed := trimPadding(b)
	if len(trimmed) == 0 {
		// The whole value was padding.
		return ""
	}
	if isPrintable(trimmed) {
		return string(trimmed)
	}
	// Genuinely binary. Hex-encode the ORIGINAL bytes, not the trimmed ones:
	// a binary identifier that happens to start or end with 0x00 must not
	// silently lose those bytes.
	return "0x" + hex.EncodeToString(b)
}

func isPrintable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// firstIP returns the first usable address from the given lists, in order.
// CDP switches vary on whether they populate the management address TLV, the
// general address TLV, or both.
func firstIP(lists ...[]net.IP) string {
	for _, list := range lists {
		for _, ip := range list {
			if len(ip) > 0 && !ip.IsUnspecified() {
				return ip.String()
			}
		}
	}
	return ""
}
