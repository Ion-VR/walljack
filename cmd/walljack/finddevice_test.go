package main

import (
	"strings"
	"testing"

	"github.com/google/gopacket/pcap"
)

// Windows device names are opaque GUIDs, so the selection logic has to accept
// the listing number and a readable fragment as well as the full name. These
// are the three things a person will actually type.
func devices() []pcap.Interface {
	return []pcap.Interface{
		{Name: `\Device\NPF_{A47B}`, Description: "WAN Miniport (Network Monitor)"},
		{Name: `\Device\NPF_{2570}`, Description: "Intel(R) Wi-Fi 6 AX201 160MHz"},
		{Name: `\Device\NPF_{C538}`, Description: "TP-LINK Gigabit Ethernet USB Adapter"},
		{Name: "eth0", Description: ""},
	}
}

func TestFindDeviceByIndex(t *testing.T) {
	d, err := findDevice(devices(), "3")
	if err != nil {
		t.Fatalf("findDevice(3): %v", err)
	}
	if d.Description != "TP-LINK Gigabit Ethernet USB Adapter" {
		t.Errorf("got %q, want the third device", d.Description)
	}
}

func TestFindDeviceIndexOutOfRange(t *testing.T) {
	for _, want := range []string{"0", "99"} {
		if _, err := findDevice(devices(), want); err == nil {
			t.Errorf("findDevice(%q) succeeded, want an out-of-range error", want)
		}
	}
}

func TestFindDeviceByExactName(t *testing.T) {
	d, err := findDevice(devices(), "eth0")
	if err != nil {
		t.Fatalf("findDevice(eth0): %v", err)
	}
	if d.Name != "eth0" {
		t.Errorf("got %q, want eth0", d.Name)
	}
}

func TestFindDeviceByFragment(t *testing.T) {
	// Case-insensitive, because nobody is typing TP-LINK in capitals twice.
	d, err := findDevice(devices(), "tp-link")
	if err != nil {
		t.Fatalf("findDevice(tp-link): %v", err)
	}
	if !strings.Contains(d.Description, "TP-LINK") {
		t.Errorf("got %q, want the TP-LINK adapter", d.Description)
	}
}

func TestFindDeviceAmbiguousFragment(t *testing.T) {
	// "wi-fi" hits the Intel adapter, and a second entry is added here so the
	// ambiguity path is exercised rather than silently picking the first.
	devs := append(devices(), pcap.Interface{
		Name:        `\Device\NPF_{3645}`,
		Description: "Microsoft Wi-Fi Direct Virtual Adapter",
	})

	_, err := findDevice(devs, "wi-fi")
	if err == nil {
		t.Fatal("findDevice(wi-fi) succeeded, want an ambiguity error naming both candidates")
	}
	for _, want := range []string{"Intel", "Microsoft"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q, the user cannot tell which to pick", err, want)
		}
	}
}

func TestFindDeviceUnknown(t *testing.T) {
	if _, err := findDevice(devices(), "nope"); err == nil {
		t.Error("findDevice(nope) succeeded, want a not-found error")
	}
}
