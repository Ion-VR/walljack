package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"time"

	"github.com/Ion-VR/walljack/internal/discovery"
)

// csvHeader is written once, when the output file is created. Column names are
// stable across protocols so a survey that mixes LLDP and CDP jacks still
// produces one tidy sheet.
var csvHeader = []string{
	"timestamp",
	"label",
	"interface",
	"protocol",
	"chassis_id",
	"port_id",
	"port_description",
	"system_name",
	"platform",
	"vlan",
	"management_ip",
	"system_description",
}

// csvLogger appends one row per neighbour to a CSV file. Appending rather than
// truncating is the point: walking a floor means running walljack once per
// jack, and every run should add to the same sheet.
type csvLogger struct {
	file *os.File
	w    *csv.Writer
}

func newCSVLogger(path string) (*csvLogger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	l := &csvLogger{file: f, w: csv.NewWriter(f)}
	if info.Size() == 0 {
		if err := l.w.Write(csvHeader); err != nil {
			f.Close()
			return nil, fmt.Errorf("writing header to %s: %w", path, err)
		}
	}
	return l, nil
}

func (l *csvLogger) Write(label, iface string, n discovery.Neighbor) error {
	return l.w.Write([]string{
		time.Now().Format(time.RFC3339),
		label,
		iface,
		string(n.Protocol),
		n.ChassisID,
		n.PortID,
		n.PortDescription,
		n.SystemName,
		n.Platform,
		n.VLAN,
		n.ManagementIP,
		n.SystemDescr,
	})
}

// WriteEmpty records a jack where nothing answered. A dead or unmanaged jack is
// a real survey result, and leaving a gap in the sheet means you cannot tell it
// apart from a jack you never got round to testing.
func (l *csvLogger) WriteEmpty(label, iface string) error {
	return l.w.Write([]string{
		time.Now().Format(time.RFC3339),
		label,
		iface,
		"none",
		"", "", "", "", "", "", "", "",
	})
}

func (l *csvLogger) Close() error {
	l.w.Flush()
	if err := l.w.Error(); err != nil {
		l.file.Close()
		return err
	}
	return l.file.Close()
}
