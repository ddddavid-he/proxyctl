//go:build linux

package preflight

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// stubReadFile swaps the internal fixed-table read boundary for the
// duration of one test.
func stubReadFile(t *testing.T, fn func(string) ([]byte, error)) {
	t.Helper()
	orig := readFile
	readFile = fn
	t.Cleanup(func() { readFile = orig })
}

const procNetCleanTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
`

const procNetCleanUDP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   1: 0100007F:C832 00000000:0000 07 00000000:00000000 00:00000000 00000000   996        0 22334 2 0000000000000000 0
`

const procNetCleanTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 45678 1 0000000000000000 100 0 0 10 0
`

const procNetCleanUDP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   1: 00000000000000000000000000000000:C832 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000   996        0 56789 2 0000000000000000 0
`

// cleanTables serves well-formed content for every fixed table: genuine
// 8-hex IPv4 rows for tcp/udp and genuine 32-hex IPv6 rows for
// tcp6/udp6.
func cleanTables(path string) ([]byte, error) {
	switch path {
	case procNetTCPPath:
		return []byte(procNetCleanTCP), nil
	case procNetUDPPath:
		return []byte(procNetCleanUDP), nil
	case procNetTCP6:
		return []byte(procNetCleanTCP6), nil
	case procNetUDP6:
		return []byte(procNetCleanUDP6), nil
	}
	return nil, os.ErrNotExist
}

func TestLinuxProbeListenersClean(t *testing.T) {
	stubReadFile(t, cleanTables)
	ls, err := linuxProbe{}.Listeners()
	if err != nil {
		t.Fatalf("listeners failed: %v", err)
	}
	if len(ls) != 4 {
		t.Fatalf("got %d listeners; want 4 (one per table): %+v", len(ls), ls)
	}
	// Spot-check the IPv6 loopback row survived width validation.
	found := false
	for _, l := range ls {
		if l.Protocol == "tcp" && l.Address == "::1" && l.Port == 8080 {
			found = true
		}
	}
	if !found {
		t.Errorf("IPv6 loopback tcp6 row missing: %+v", ls)
	}
}

// TestLinuxProbeListenersIPv6ENOENTSkipped proves missing IPv6 tables
// (IPv6 disabled) do not fail the scan.
func TestLinuxProbeListenersIPv6ENOENTSkipped(t *testing.T) {
	stubReadFile(t, func(path string) ([]byte, error) {
		if path == procNetTCP6 || path == procNetUDP6 {
			return nil, os.ErrNotExist
		}
		return cleanTables(path)
	})
	ls, err := linuxProbe{}.Listeners()
	if err != nil {
		t.Fatalf("listeners failed with IPv6 ENOENT: %v", err)
	}
	if len(ls) != 2 {
		t.Fatalf("got %d listeners; want 2 (IPv4 tables only): %+v", len(ls), ls)
	}
}

// TestLinuxProbeListenersReadFailuresFail proves unreadable required
// tables and non-ENOENT IPv6 errors fail the scan with a fixed,
// canary-free error.
func TestLinuxProbeListenersReadFailuresFail(t *testing.T) {
	canary := errors.New("canary-kernel-ioperm-7 denied")
	cases := []struct {
		name string
		path string // which table fails
		err  error
	}{
		{"required tcp unreadable", procNetTCPPath, canary},
		{"required udp unreadable", procNetUDPPath, canary},
		{"required tcp ENOENT", procNetTCPPath, os.ErrNotExist},
		{"ipv6 tcp non-ENOENT read error", procNetTCP6, canary},
		{"ipv6 udp non-ENOENT read error", procNetUDP6, canary},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubReadFile(t, func(path string) ([]byte, error) {
				if path == tc.path {
					return nil, tc.err
				}
				return cleanTables(path)
			})
			_, err := linuxProbe{}.Listeners()
			if err == nil {
				t.Fatal("unreadable table did not fail the scan")
			}
			if strings.Contains(err.Error(), "canary") {
				t.Errorf("canary leaked into error: %q", err.Error())
			}
		})
	}
}

// TestLinuxProbeListenersMalformedTableFails proves a readable table
// with a malformed row fails the whole scan (fail closed).
func TestLinuxProbeListenersMalformedTableFails(t *testing.T) {
	stubReadFile(t, func(path string) ([]byte, error) {
		if path == procNetUDPPath {
			return []byte("  sl  local_address rem_address   st\n   0: canary-malformed-row\n"), nil
		}
		return cleanTables(path)
	})
	_, err := linuxProbe{}.Listeners()
	if err == nil {
		t.Fatal("malformed readable table did not fail the scan")
	}
	if strings.Contains(err.Error(), "canary") {
		t.Errorf("canary leaked into error: %q", err.Error())
	}
}
