package preflight

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
)

// This file parses the fixed Linux /proc/net/{tcp,tcp6,udp,udp6} table
// format. It contains no OS-specific calls so the deterministic parser
// tests run on any host; only the file-reading probe methods are
// build-tagged to Linux (see probe_linux.go).

// tcpStateListen is the /proc/net/tcp state value for LISTEN sockets.
const tcpStateListen = "0A"

// parseProcNet parses one /proc/net/{tcp,tcp6,udp,udp6} table. proto is
// "tcp" or "udp"; is6 selects the 32-hex-digit IPv6 address form.
// Parsing is strict and fail-closed: any malformed non-header row is
// an error, so a reserved listener can never be silently skipped. For
// TCP, only LISTEN rows are returned; for UDP every bound entry is
// returned (bound UDP entries are conflict candidates).
func parseProcNet(data string, proto string, is6 bool) ([]Listener, error) {
	var out []Listener
	for i, line := range strings.Split(data, "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // header or blank
		}
		l, ok, err := parseProcNetLine(line, proto, is6)
		if err != nil {
			return nil, fmt.Errorf("row %d: %w", i+1, err)
		}
		if !ok {
			continue // well-formed non-LISTEN TCP row
		}
		out = append(out, l)
	}
	return out, nil
}

// parseProcNetLine parses a single data row. It extracts only the local
// address field (index 1) and the state field (index 3); all other
// fields are ignored. The local address is validated BEFORE the TCP
// state check so a malformed local field can never be bypassed by a
// non-LISTEN state. ok is false for well-formed TCP rows that are not
// in LISTEN state; err is non-nil for any malformed row.
func parseProcNetLine(line, proto string, is6 bool) (l Listener, ok bool, err error) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return Listener{}, false, fmt.Errorf("too few fields")
	}
	addr, port, err := parseProcNetLocalAddr(fields[1], is6)
	if err != nil {
		return Listener{}, false, err
	}
	if proto == "tcp" && fields[3] != tcpStateListen {
		return Listener{}, false, nil // only LISTEN rows are listeners
	}
	return Listener{Protocol: proto, Address: addr.String(), Port: port}, true, nil
}

// parseProcNetLocalAddr parses the "HEXADDR:HEXPORT" local_address
// field with exact widths: 8 hex digits for IPv4, 32 for IPv6, and
// exactly 4 hex digits for the port. Addresses are stored little-endian
// per 32-bit word.
func parseProcNetLocalAddr(field string, is6 bool) (netip.Addr, uint16, error) {
	hexAddr, hexPort, ok := strings.Cut(field, ":")
	if !ok {
		return netip.Addr{}, 0, fmt.Errorf("missing port separator")
	}
	wantAddrLen := 8
	if is6 {
		wantAddrLen = 32
	}
	if len(hexAddr) != wantAddrLen {
		return netip.Addr{}, 0, fmt.Errorf("address field is %d hex digits, want %d", len(hexAddr), wantAddrLen)
	}
	if len(hexPort) != 4 {
		return netip.Addr{}, 0, fmt.Errorf("port field is %d hex digits, want 4", len(hexPort))
	}
	raw, err := hex.DecodeString(hexAddr)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("bad address hex")
	}
	var addr netip.Addr
	if is6 {
		var b [16]byte
		for w := 0; w < 4; w++ {
			binary.LittleEndian.PutUint32(b[w*4:], binary.BigEndian.Uint32(raw[w*4:]))
		}
		addr = netip.AddrFrom16(b)
	} else {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], binary.BigEndian.Uint32(raw))
		addr = netip.AddrFrom4(b)
	}
	p64, err := parseHexUint(hexPort)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	return addr, uint16(p64), nil
}

// parseHexUint parses a fixed-width uppercase-or-lowercase hex field.
func parseHexUint(s string) (uint64, error) {
	var v uint64
	for _, c := range s {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= uint64(c - '0')
		case c >= 'a' && c <= 'f':
			v |= uint64(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			v |= uint64(c - 'A' + 10)
		default:
			return 0, fmt.Errorf("invalid hex digit")
		}
	}
	return v, nil
}
