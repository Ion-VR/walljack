// Command walljack listens for LLDP and CDP advertisements on a chosen network
// interface and prints what switch and port the cable (wall jack) is connected
// to.
//
// Usage:
//
//	walljack                            # interactive: pick an interface, stop at the first answer
//	walljack -l                         # list interfaces and exit
//	walljack -i 6                       # skip the picker, using the number from -l
//	walljack -i eth0                    # ...or a name, or an unambiguous fragment of one
//	walljack -d 60s                     # change the maximum listen time
//	walljack -all                       # keep listening, collect every neighbour
//	walljack -o jacks.csv               # append the result to a CSV file
//	walljack -o jacks.csv -label B214   # ...tagged with the room or jack reference
//
// Switches emit discovery frames roughly every 30 seconds, so the 35s default
// is long enough to catch at least one from most gear. walljack stops as soon
// as it hears one, so in practice it usually returns in a few seconds.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/Ion-VR/walljack/internal/console"
	"github.com/Ion-VR/walljack/internal/discovery"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	snapLen     = 65536
	promiscuous = true
)

// version is overwritten at build time with -ldflags "-X main.version=v1.2.3".
var version = "dev"

type options struct {
	iface    string
	duration time.Duration
	listOnly bool
	all      bool
	csvPath  string
	label    string
}

func main() {
	var (
		opts        options
		showVersion bool
	)
	flag.StringVar(&opts.iface, "i", "", "interface to capture on: the number from -l, a name, or part of one")
	flag.DurationVar(&opts.duration, "d", 35*time.Second, "maximum time to listen for discovery frames")
	flag.BoolVar(&opts.listOnly, "l", false, "list available interfaces and exit")
	flag.BoolVar(&opts.all, "all", false, "keep listening for the full duration instead of stopping at the first neighbour")
	flag.StringVar(&opts.csvPath, "o", "", "append results to this CSV file (created if absent)")
	flag.StringVar(&opts.label, "label", "", "room or jack reference recorded in the CSV row")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Printf("walljack %s\n", version)
		return
	}

	code := 0
	if err := run(opts); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		code = 1
	}

	// Double-clicked from Explorer, the console window belongs to us and closes
	// the moment we return, taking the answer with it. Hold it open instead.
	if console.OwnsWindow() {
		fmt.Print("\nPress Enter to close...")
		bufio.NewReader(os.Stdin).ReadString('\n')
	}
	os.Exit(code)
}

func run(opts options) error {
	if opts.label != "" && opts.csvPath == "" {
		return fmt.Errorf("-label only means something with -o: pass a CSV file to write to")
	}

	devices, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("listing interfaces (is Npcap/libpcap installed?): %w", err)
	}
	if len(devices) == 0 {
		return fmt.Errorf("no capture interfaces found, check the Npcap/libpcap install and that you are running elevated")
	}

	if opts.listOnly {
		printInterfaces(devices)
		return nil
	}

	device, err := selectDevice(devices, opts.iface)
	if err != nil {
		return err
	}

	// Ctrl+C ends the capture early but still prints and records whatever was
	// collected up to that point.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if opts.all {
		fmt.Printf("\nListening on %s for %s (Ctrl+C to stop early)...\n", deviceLabel(device), opts.duration)
	} else {
		fmt.Printf("\nListening on %s, up to %s (stops at the first answer, Ctrl+C to give up)...\n",
			deviceLabel(device), opts.duration)
	}

	neighbors, err := capture(ctx, device.Name, opts.duration, opts.all)
	if err != nil {
		return err
	}

	printNeighbors(neighbors)

	if opts.csvPath != "" {
		if err := writeCSV(opts, device.Name, neighbors); err != nil {
			return err
		}
		fmt.Printf("\nAppended %s to %s\n", rowWord(len(neighbors)), opts.csvPath)
	}
	return nil
}

// capture opens the device, filters for LLDP and CDP, and collects unique
// neighbours. It returns as soon as the first neighbour is seen unless all is
// set, in which case it listens for the whole window.
func capture(ctx context.Context, deviceName string, duration time.Duration, all bool) ([]discovery.Neighbor, error) {
	handle, err := pcap.OpenLive(deviceName, snapLen, promiscuous, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("opening %s (are you running elevated?): %w", deviceName, err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(discovery.BPFFilter); err != nil {
		return nil, fmt.Errorf("setting discovery filter: %w", err)
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := source.Packets()
	deadline := time.After(duration)

	seen := make(map[string]struct{})
	var neighbors []discovery.Neighbor

	for {
		select {
		case <-ctx.Done():
			return neighbors, nil
		case <-deadline:
			return neighbors, nil
		case packet, ok := <-packets:
			if !ok {
				return neighbors, nil
			}
			n, ok := discovery.Parse(packet)
			if !ok {
				continue
			}
			if _, dup := seen[n.Key()]; dup {
				continue
			}
			seen[n.Key()] = struct{}{}
			neighbors = append(neighbors, n)
			fmt.Printf("  found %s neighbour: %s / %s\n", n.Protocol, n.ChassisID, n.PortID)

			if !all {
				return neighbors, nil
			}
		}
	}
}

func writeCSV(opts options, iface string, neighbors []discovery.Neighbor) error {
	logger, err := newCSVLogger(opts.csvPath)
	if err != nil {
		return err
	}
	defer logger.Close()

	if len(neighbors) == 0 {
		return logger.WriteEmpty(opts.label, iface)
	}
	for _, n := range neighbors {
		if err := logger.Write(opts.label, iface, n); err != nil {
			return fmt.Errorf("writing row: %w", err)
		}
	}
	return nil
}

// selectDevice resolves the capture device either from the -i flag or via an
// interactive numbered prompt.
//
// -i deliberately accepts three things, because the full device name on Windows
// is an opaque GUID that nobody is going to type:
//
//	-i 6                 the number from the -l listing
//	-i eth0              an exact name or description
//	-i TP-LINK           any unambiguous fragment of one
func selectDevice(devices []pcap.Interface, ifaceName string) (pcap.Interface, error) {
	if ifaceName != "" {
		return findDevice(devices, ifaceName)
	}

	printInterfaces(devices)
	fmt.Print("\nSelect interface number: ")

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return pcap.Interface{}, fmt.Errorf("reading selection: %w", err)
	}
	idx, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || idx < 1 || idx > len(devices) {
		return pcap.Interface{}, fmt.Errorf("invalid selection %q", strings.TrimSpace(line))
	}
	return devices[idx-1], nil
}

func findDevice(devices []pcap.Interface, want string) (pcap.Interface, error) {
	// A bare number is the index from the listing, which is the first thing
	// anyone tries after running -l.
	if idx, err := strconv.Atoi(want); err == nil {
		if idx < 1 || idx > len(devices) {
			return pcap.Interface{}, fmt.Errorf(
				"interface %d is out of range, there are %d (try -l to list)", idx, len(devices))
		}
		return devices[idx-1], nil
	}

	for _, d := range devices {
		if strings.EqualFold(d.Name, want) || strings.EqualFold(d.Description, want) {
			return d, nil
		}
	}

	// Fall back to a fragment match so "-i TP-LINK" works.
	var matches []pcap.Interface
	needle := strings.ToLower(want)
	for _, d := range devices {
		if strings.Contains(strings.ToLower(d.Name), needle) ||
			strings.Contains(strings.ToLower(d.Description), needle) {
			matches = append(matches, d)
		}
	}

	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return pcap.Interface{}, fmt.Errorf("interface %q not found (try -l to list)", want)
	default:
		var names []string
		for _, d := range matches {
			names = append(names, deviceLabel(d))
		}
		return pcap.Interface{}, fmt.Errorf("interface %q is ambiguous, it matches:\n  %s",
			want, strings.Join(names, "\n  "))
	}
}

func printInterfaces(devices []pcap.Interface) {
	fmt.Println("Available interfaces:")
	for i, d := range devices {
		fmt.Printf("  [%d] %s\n", i+1, deviceLabel(d))
		for _, addr := range d.Addresses {
			if addr.IP != nil {
				fmt.Printf("        addr: %s\n", addr.IP)
			}
		}
	}
}

// deviceLabel prefers the human-readable description (Windows device names are
// opaque GUIDs) but always shows the underlying name too.
func deviceLabel(d pcap.Interface) string {
	if d.Description != "" {
		return fmt.Sprintf("%s (%s)", d.Description, d.Name)
	}
	return d.Name
}

func printNeighbors(neighbors []discovery.Neighbor) {
	if len(neighbors) == 0 {
		fmt.Println("\nNo LLDP or CDP advertisements seen.")
		fmt.Println("Tips: the jack may be on an unmanaged switch, both protocols may be")
		fmt.Println("disabled on the port, or the frame is being consumed by a switch")
		fmt.Println("before it reaches this host. Try -d 90s in case the interval is long.")
		return
	}

	for i, n := range neighbors {
		fmt.Printf("\n=== %s neighbour %d of %d ===\n", n.Protocol, i+1, len(neighbors))
		printField(n.ChassisLabel(), n.ChassisID)
		printField("Port ID", n.PortID)
		printField("Port Description", n.PortDescription)
		printField("System Name", n.SystemName)
		if n.Platform != "" {
			printField("Platform", n.Platform)
		}
		printField("VLAN", n.VLAN)
		printField("Management IP", n.ManagementIP)
		if n.SystemDescr != "" {
			printField("System Description", n.SystemDescr)
		}
	}
}

func printField(label, value string) {
	if value == "" {
		value = "(not advertised)"
	}
	fmt.Printf("  %-18s: %s\n", label, value)
}

func rowWord(n int) string {
	if n == 0 {
		return "1 row (no neighbour found)"
	}
	if n == 1 {
		return "1 row"
	}
	return fmt.Sprintf("%d rows", n)
}
