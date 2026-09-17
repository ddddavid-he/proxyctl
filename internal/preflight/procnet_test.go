package preflight

import (
	"testing"
)

// The fixtures below mirror the fixed kernel format of
// /proc/net/{tcp,tcp6,udp,udp6}: a header line followed by rows whose
// local_address is "HEXADDR:HEXPORT" (little-endian per 32-bit word)
// and whose st field is "0A" for TCP LISTEN.

const procNetTCPFixture = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000:20FB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 23456 1 0000000000000000 100 0 0 10 0
   2: 0100007F:0016 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 34567 1 0000000000000000 100 0 0 10 0
`

const procNetTCP6Fixture = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:20FC 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 45678 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 56789 1 0000000000000000 100 0 0 10 0
   2: 00000000000000000000000001000000:20FC 00000000000000000000000000000000:0000 06 00000000:00000000 00:00000000 00000000  1000        0 67890 1 0000000000000000 100 0 0 10 0
`

const procNetUDPFixture = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   0: 00000000:01BB 00000000:0000 07 00000000:00000000 00:00000000 00000000   996        0 11223 2 0000000000000000 0
   1: 0100007F:C832 00000000:0000 07 00000000:00000000 00:00000000 00000000   996        0 22334 2 0000000000000000 0
`

func TestParseProcNetTCP(t *testing.T) {
	ls, err := parseProcNet(procNetTCPFixture, "tcp", false)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(ls) != 2 {
		t.Fatalf("got %d listeners; want 2 (non-LISTEN row must be dropped): %+v", len(ls), ls)
	}
	// 0100007F:1F90 -> 127.0.0.1:8080 (IPv4 loopback)
	if ls[0].Protocol != "tcp" || ls[0].Address != "127.0.0.1" || ls[0].Port != 8080 {
		t.Errorf("row 0 = %+v; want tcp 127.0.0.1:8080", ls[0])
	}
	// 00000000:20FB -> 0.0.0.0:8443 (IPv4 wildcard, gateway trojan port)
	if ls[1].Protocol != "tcp" || ls[1].Address != "0.0.0.0" || ls[1].Port != 8443 {
		t.Errorf("row 1 = %+v; want tcp 0.0.0.0:8443", ls[1])
	}
}

func TestParseProcNetTCP6(t *testing.T) {
	ls, err := parseProcNet(procNetTCP6Fixture, "tcp", true)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(ls) != 2 {
		t.Fatalf("got %d listeners; want 2 (TIME_WAIT row must be dropped): %+v", len(ls), ls)
	}
	// ...01000000:20FC -> ::1:8444 (IPv6 loopback, gateway https port)
	if ls[0].Protocol != "tcp" || ls[0].Address != "::1" || ls[0].Port != 8444 {
		t.Errorf("row 0 = %+v; want tcp ::1:8444", ls[0])
	}
	// all-zero:01BB -> [::]:443 (IPv6 wildcard)
	if ls[1].Protocol != "tcp" || ls[1].Address != "::" || ls[1].Port != 443 {
		t.Errorf("row 1 = %+v; want tcp :::443", ls[1])
	}
}

func TestParseProcNetUDPBoundEntriesReturned(t *testing.T) {
	ls, err := parseProcNet(procNetUDPFixture, "udp", false)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(ls) != 2 {
		t.Fatalf("got %d listeners; want 2 (bound UDP entries are conflict candidates): %+v", len(ls), ls)
	}
	// 00000000:01BB -> 0.0.0.0:443 (egress hysteria2 reservation)
	if ls[0].Protocol != "udp" || ls[0].Address != "0.0.0.0" || ls[0].Port != 443 {
		t.Errorf("row 0 = %+v; want udp 0.0.0.0:443", ls[0])
	}
	// 0100007F:C832 -> 127.0.0.1:51250 (unrelated bound UDP)
	if ls[1].Protocol != "udp" || ls[1].Address != "127.0.0.1" || ls[1].Port != 51250 {
		t.Errorf("row 1 = %+v; want udp 127.0.0.1:51250", ls[1])
	}
}

// TestParseProcNetMalformedRowsFail proves malformed non-header rows
// are errors (fail closed), never silently skipped — a malformed row
// could otherwise hide a reserved listener.
func TestParseProcNetMalformedRowsFail(t *testing.T) {
	cases := []struct {
		name  string
		data  string
		proto string
		is6   bool
	}{
		{"no port separator", "  sl  local_address rem_address   st\n   0: 0100007F 00000000:0000 0A\n", "tcp", false},
		{"bad address hex", "  sl  local_address rem_address   st\n   0: ZZ00007F:1F90 00000000:0000 0A\n", "tcp", false},
		{"ipv4 address too wide", "  sl  local_address rem_address   st\n   0: 0100007F00:1F90 00000000:0000 0A\n", "tcp", false},
		{"ipv4 address too narrow", "  sl  local_address rem_address   st\n   0: 00007F:1F90 00000000:0000 0A\n", "tcp", false},
		{"bad port hex", "  sl  local_address rem_address   st\n   0: 0100007F:XYZW 00000000:0000 0A\n", "tcp", false},
		{"port too wide", "  sl  local_address rem_address   st\n   0: 0100007F:01F90 00000000:0000 0A\n", "tcp", false},
		{"port too narrow", "  sl  local_address rem_address   st\n   0: 0100007F:1F9 00000000:0000 0A\n", "tcp", false},
		{"too few fields", "  sl  local_address rem_address   st\n   0: 0100007F:1F90\n", "tcp", false},
		{"ipv6 address wrong width", "  sl  local_address rem_address   st\n   0: 00000000:01BB 00000000:0000 07\n", "udp", true},
		{"malformed row AFTER a valid listener still fails", procNetTCPFixture + "   9: garbage-row\n", "tcp", false},
		// A malformed local address must fail even when the TCP state
		// is non-LISTEN: state-based dropping must not bypass
		// validation.
		{"malformed local address with non-LISTEN state fails", "  sl  local_address rem_address   st\n   0: 0100:1F90 00000000:0000 01\n", "tcp", false},
		{"missing port separator with non-LISTEN state fails", "  sl  local_address rem_address   st\n   0: 0100007F 00000000:0000 06\n", "tcp", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ls, err := parseProcNet(tc.data, tc.proto, tc.is6)
			if err == nil {
				t.Fatalf("malformed row did not fail; listeners: %+v", ls)
			}
			if ls != nil {
				t.Errorf("failed parse returned listeners: %+v", ls)
			}
		})
	}
}

// TestParseProcNetExactReservationPorts proves the parser surfaces the
// exact ports of the role reservation matrix from realistic rows.
func TestParseProcNetExactReservationPorts(t *testing.T) {
	data := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:20FB 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1 1 0000000000000000 100 0 0 10 0
   1: 00000000:20FC 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 2 1 0000000000000000 100 0 0 10 0
   2: 0100007F:1ED2 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 3 1 0000000000000000 100 0 0 10 0
`
	ls, err := parseProcNet(data, "tcp", false)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	want := []Listener{
		{Protocol: "tcp", Address: "0.0.0.0", Port: 8443},
		{Protocol: "tcp", Address: "0.0.0.0", Port: 8444},
		{Protocol: "tcp", Address: "127.0.0.1", Port: 7890},
	}
	if len(ls) != len(want) {
		t.Fatalf("got %d listeners; want %d: %+v", len(ls), len(want), ls)
	}
	for i := range want {
		if ls[i] != want[i] {
			t.Errorf("row %d = %+v; want %+v", i, ls[i], want[i])
		}
	}
}
