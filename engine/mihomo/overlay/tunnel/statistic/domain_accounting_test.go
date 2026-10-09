// SPDX-License-Identifier: GPL-3.0-or-later
package statistic

import (
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	C "github.com/metacubex/mihomo/constant"
)

type testConn struct{ C.Conn }

func (testConn) RemoteDestination() string       { return "" }
func (testConn) Chains() C.Chain                 { return nil }
func (testConn) ProviderChains() C.Chain         { return nil }
func (testConn) Read(b []byte) (int, error)      { return len(b), nil }
func (testConn) Write(b []byte) (int, error)     { return len(b), nil }
func (testConn) ReadBuffer(b *buf.Buffer) error  { _, err := b.Write([]byte("abc")); return err }
func (testConn) WriteBuffer(b *buf.Buffer) error { return nil }
func (testConn) Close() error                    { return nil }

type testPacket struct{ C.PacketConn }

func (testPacket) RemoteDestination() string                { return "" }
func (testPacket) Chains() C.Chain                          { return nil }
func (testPacket) ProviderChains() C.Chain                  { return nil }
func (testPacket) ReadFrom(b []byte) (int, net.Addr, error) { return len(b), nil, nil }
func (testPacket) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	return []byte("abc"), func() {}, nil, nil
}
func (testPacket) WriteTo(b []byte, a net.Addr) (int, error) { return len(b), nil }
func (testPacket) Close() error                              { return nil }

func testJournal(t *testing.T) *domainJournal {
	t.Helper()
	j := &domainJournal{dir: t.TempDir(), epoch: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", from: time.Now().Unix(), rows: make(map[domainKey]*domainRow)}
	old := domainAccounting
	domainAccounting = j
	t.Cleanup(func() { domainAccounting = old })
	return j
}
func TestAllTrackerPathsAndClosedConnections(t *testing.T) {
	j := testJournal(t)
	m := &Manager{}
	metadata := &C.Metadata{Host: "Example.COM."}
	tcp := NewTCPTracker(testConn{}, m, metadata, nil, 5, 7, true)
	tcp.Read(make([]byte, 11))
	tcp.Write(make([]byte, 13))
	b := buf.New()
	tcp.ReadBuffer(b)
	b.Release()
	b = buf.New()
	b.Write([]byte("abcde"))
	tcp.WriteBuffer(b)
	b.Release()
	_, read := tcp.UnwrapReader()
	read[0](17)
	_, write := tcp.UnwrapWriter()
	write[0](19)
	tcp.Close()
	udp := NewUDPTracker(testPacket{}, m, metadata, nil, 23, 29, true)
	udp.ReadFrom(make([]byte, 31))
	udp.WaitReadFrom()
	udp.WriteTo(make([]byte, 37), nil)
	udp.Close()
	// Nested outbound trackers must never count gateway bytes twice.
	nested := NewTCPTracker(testConn{}, m, metadata, nil, 1000, 2000, false)
	nested.Read(make([]byte, 100))
	nested.Write(make([]byte, 100))
	nested.Close()
	if m.Get(tcp.ID()) != nil || m.Get(udp.ID()) != nil {
		t.Fatal("connections still active")
	}
	if err := j.flush(); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(j.dir, "*.json"))
	data, _ := os.ReadFile(files[0])
	var batch domainBatch
	if err := json.Unmarshal(data, &batch); err != nil {
		t.Fatal(err)
	}
	up, down := m.Total()
	if len(batch.Rows) != 1 || batch.Rows[0].Domain != "example.com" || batch.Rows[0].Upload != up || batch.Rows[0].Download != down {
		t.Fatalf("batch=%+v global=%d/%d", batch, up, down)
	}
	if up != 102 || down != 101 {
		t.Fatalf("unexpected path counts %d/%d", up, down)
	}
}
func TestConcurrentCountersSurviveFlush(t *testing.T) {
	j := testJournal(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 1000; n++ {
				recordDomain("example.com", 1, 2)
			}
		}()
	}
	if err := j.flush(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if err := j.flush(); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(j.dir, "*.json"))
	var up, down int64
	for _, f := range files {
		data, _ := os.ReadFile(f)
		var batch domainBatch
		json.Unmarshal(data, &batch)
		for _, row := range batch.Rows {
			up += row.Upload
			down += row.Download
		}
	}
	if up != 8000 || down != 16000 {
		t.Fatalf("lost concurrent bytes %d/%d", up, down)
	}
}
func TestFailedFlushKeepsUncommittedBytes(t *testing.T) {
	j := testJournal(t)
	recordDomain("example.com", 10, 20)
	os.Mkdir(filepath.Join(j.dir, ".batch.tmp"), 0700)
	if err := j.flush(); err == nil {
		t.Fatal("expected disk error")
	}
	if j.seq != 0 || len(j.rows) != 1 {
		t.Fatal("discarded failed batch")
	}
	os.Remove(filepath.Join(j.dir, ".batch.tmp"))
	if err := j.flush(); err != nil {
		t.Fatal(err)
	}
}
func TestHostPrivacyAndIPFallback(t *testing.T) {
	for _, test := range []struct{ host, want string }{{"Example.COM.", "example.com"}, {"https://example.com/private", "[ip-only]"}, {"192.0.2.1", "[ip-only]"}, {"", "[ip-only]"}, {"例子.测试", "xn--fsqu00a.xn--0zwm56d"}} {
		got := accountingDomain(&C.Metadata{Host: test.host, DstIP: netip.MustParseAddr("192.0.2.1")})
		if got != test.want {
			t.Fatalf("%s: %s", test.host, got)
		}
	}
}
func TestDomainCapacityPreservesBytes(t *testing.T) {
	j := testJournal(t)
	for i := 0; i < 10001; i++ {
		j.add(string(rune(i)), 1, 2, time.Now())
	}
	var up, down int64
	found := false
	for _, row := range j.rows {
		up += row.Upload
		down += row.Download
		if row.Domain == "[domain-limit]" {
			found = true
		}
	}
	if up != 10001 || down != 20002 || !found {
		t.Fatal("capacity lost totals")
	}
}
