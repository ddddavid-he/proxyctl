// SPDX-License-Identifier: GPL-3.0-or-later
// proxyctl extension: count payload bytes at the gateway tracker, independently
// of connection lifetime. Immutable fsynced batches are acknowledged by SQLite.
package statistic

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"golang.org/x/net/idna"
)

type domainRow struct {
	Start    int64  `json:"start"`
	Domain   string `json:"domain"`
	Upload   int64  `json:"upload"`
	Download int64  `json:"download"`
}
type domainBatch struct {
	Version         int         `json:"version"`
	EmittedNS       int64       `json:"emitted_ns"`
	Epoch           string      `json:"epoch"`
	Sequence        uint64      `json:"sequence"`
	From            int64       `json:"from"`
	To              int64       `json:"to"`
	UncleanPrevious bool        `json:"unclean_previous"`
	Rows            []domainRow `json:"rows"`
}
type domainKey struct {
	start  int64
	domain string
}
type domainJournal struct {
	mu         sync.Mutex
	dir, epoch string
	seq        uint64
	from       int64
	unclean    bool
	rows       map[domainKey]*domainRow
	lock       *os.File
	stop       chan struct{}
	done       chan struct{}
}

var domainAccounting *domainJournal

func accountingDomain(metadata *C.Metadata) string {
	for _, value := range []string{metadata.Host, metadata.SniffHost} {
		value = strings.TrimSuffix(value, ".")
		if _, err := netip.ParseAddr(strings.Trim(value, "[]")); err == nil {
			continue
		}
		host, err := idna.Lookup.ToASCII(value)
		host = strings.ToLower(host)
		if err != nil || len(host) == 0 || len(host) > 253 {
			continue
		}
		valid := true
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				valid = false
				break
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					valid = false
				}
			}
		}
		if valid {
			return host
		}
	}
	if metadata.DstIP.IsValid() {
		return "[ip-only]"
	}
	return "[unknown-domain]"
}

func (j *domainJournal) add(host string, up, down int64, now time.Time) {
	if up <= 0 && down <= 0 {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	at := now.Unix()
	if at < j.from {
		at = j.from
	}
	key := domainKey{at / 900 * 900, host}
	if _, ok := j.rows[key]; !ok && len(j.rows) >= 10000 {
		key.domain = "[domain-limit]"
	}
	row := j.rows[key]
	if row == nil {
		row = &domainRow{Start: key.start, Domain: key.domain}
		j.rows[key] = row
	}
	row.Upload += up
	row.Download += down
}
func recordDomain(host string, up, down int64) {
	if domainAccounting != nil {
		domainAccounting.add(host, up, down, time.Now())
	}
}

func syncDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func (j *domainJournal) flush() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	entries, err := os.ReadDir(j.dir)
	if err != nil {
		return err
	}
	// Collector outage must fail visibly rather than silently dropping a batch.
	if len(entries) > 10000 {
		return errors.New("accounting spool capacity exceeded")
	}
	stamp := time.Now()
	now := stamp.Unix()
	if now < j.from {
		return errors.New("accounting clock moved backwards")
	}
	rows := make([]domainRow, 0, len(j.rows))
	for _, row := range j.rows {
		rows = append(rows, *row)
	}
	sort.Slice(rows, func(i, k int) bool {
		if rows[i].Start != rows[k].Start {
			return rows[i].Start < rows[k].Start
		}
		return rows[i].Domain < rows[k].Domain
	})
	batch := domainBatch{1, stamp.UnixNano(), j.epoch, j.seq + 1, j.from, now, j.unclean, rows}
	data, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	name := fmt.Sprintf("%s-%020d.json", j.epoch, batch.Sequence)
	temporary := filepath.Join(j.dir, ".batch.tmp")
	f, err := os.OpenFile(temporary, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	// A privileged gateway and an unprivileged collector share a configured group.
	if err = f.Chmod(0640); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(temporary, filepath.Join(j.dir, name)); err != nil {
		return err
	}
	if err = syncDirectory(j.dir); err != nil {
		return err
	}
	j.rows = make(map[domainKey]*domainRow)
	j.seq++
	j.from = now
	j.unclean = false
	return nil
}

// StartDomainAccounting must run before listeners start. Empty dir disables it.
func StartDomainAccounting(dir string) error {
	if dir == "" {
		return nil
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("invalid accounting directory")
	}
	lock, err := os.OpenFile(filepath.Join(dir, ".writer.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return err
	}
	fail := func(err error) error { lock.Close(); return err }
	seed := make([]byte, 16)
	if _, err = rand.Read(seed); err != nil {
		return fail(err)
	}
	_, markerErr := os.Stat(filepath.Join(dir, ".running"))
	if markerErr != nil && !os.IsNotExist(markerErr) {
		return fail(markerErr)
	}
	j := &domainJournal{dir: dir, epoch: hex.EncodeToString(seed), from: time.Now().Unix(), unclean: markerErr == nil, rows: make(map[domainKey]*domainRow), lock: lock, stop: make(chan struct{}), done: make(chan struct{})}
	marker, err := os.OpenFile(filepath.Join(dir, ".running"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return fail(err)
	}
	_, err = marker.WriteString(j.epoch)
	if err == nil {
		err = marker.Sync()
	}
	marker.Close()
	if err != nil {
		return fail(err)
	}
	if err = syncDirectory(dir); err != nil {
		return fail(err)
	}
	if err = j.flush(); err != nil {
		return fail(err)
	}
	domainAccounting = j
	go func() {
		defer close(j.done)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-j.stop:
				return
			case <-ticker.C:
				if j.flush() != nil {
					fmt.Fprintln(os.Stderr, "domain accounting durability failure")
					os.Exit(1)
				}
			}
		}
	}()
	return nil
}

// Keep the crash marker on shutdown as well: existing relay goroutines can
// still race process exit. The next run conservatively exposes possible tail loss.
func StopDomainAccounting() {
	j := domainAccounting
	if j == nil {
		return
	}
	close(j.stop)
	<-j.done
	if j.flush() != nil {
		fmt.Fprintln(os.Stderr, "domain accounting final flush failed")
	}
	j.lock.Close()
}
