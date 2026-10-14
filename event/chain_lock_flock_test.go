//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package event

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The tests here need a lock that really excludes another open file and
// another process, which flock(2) is and lock_other.go is not.

// tryLock reports whether path can be locked exclusively right now from a
// fresh open file, without waiting, and releases the lock if it got it.
func tryLock(t *testing.T, path string) error {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open probe: %v", err)
	}
	defer f.Close()
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	}
	return err
}

// assertEveryWriterComplete requires every writer's events to be present
// exactly once and in the order that writer wrote them.
func assertEveryWriterComplete(t *testing.T, path string, writers, each int) {
	t.Helper()
	events, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	next := make([]int, writers)
	for i, e := range events {
		w, okW := e.Data["writer"].(float64)
		s, okS := e.Data["seq"].(float64)
		if !okW || !okS || int(w) < 0 || int(w) >= writers {
			t.Fatalf("event %d carries no valid writer/seq: %v", i, e.Data)
		}
		if int(s) != next[int(w)] {
			t.Fatalf("event %d: writer %d seq %d, want seq %d", i, int(w), int(s), next[int(w)])
		}
		next[int(w)]++
	}
	for w, n := range next {
		if n != each {
			t.Fatalf("writer %d: %d events on disk, wrote %d", w, n, each)
		}
	}
}

// Writers on one file, some sharing a ChainedWriter between goroutines and
// some with one each (one open file each, as separate processes have), all
// appending at once, swept over 12 seeds of writer count, events per writer
// and line length, a tenth of the lines longer than the first read from the
// end. Every sweep must leave one unbroken chain holding every event, each
// writer's in the order it wrote them.
func TestConcurrentWritersOnOneFileKeepOneChain(t *testing.T) {
	for seed := uint64(1); seed <= 12; seed++ {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			rng := rand.New(rand.NewPCG(seed, 2026))
			writers := 2 + rng.IntN(7)
			each := 20 + rng.IntN(61)
			pads := make([][]int, writers)
			for w := range pads {
				pads[w] = make([]int, each)
				for i := range pads[w] {
					pads[w][i] = rng.IntN(300)
					if rng.IntN(10) == 0 {
						pads[w][i] = tailChunk + rng.IntN(2*tailChunk)
					}
				}
			}

			path := filepath.Join(t.TempDir(), "bus.ndjson")
			// Writers 0 and 1 share one ChainedWriter; every other has its own.
			shared := mustWriter(t, path)
			start := make(chan struct{})
			errs := make(chan error, writers)
			var wg sync.WaitGroup
			for w := range writers {
				cw := shared
				if w >= 2 {
					cw = mustWriter(t, path)
				}
				wg.Go(func() {
					<-start
					for i := range each {
						if err := cw.Write(writerEvent(w, i, pads[w][i])); err != nil {
							errs <- fmt.Errorf("writer %d event %d: %w", w, i, err)
							return
						}
					}
				})
			}
			close(start)
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Fatal(err)
			}
			assertOneChain(t, path, writers*each)
			assertEveryWriterComplete(t, path, writers, each)
		})
	}
}

const helperMarker = "chained-writer-helper"

// TestMain runs this test binary as one writer process when it is started
// with arguments after "--" that begin with helperMarker, which is how
// TestConcurrentProcessesOnOneFileKeepOneChain starts its writers; any other
// way it runs the tests.
func TestMain(m *testing.M) {
	flag.Parse()
	if args := flag.Args(); len(args) == 5 && args[0] == helperMarker {
		if err := writerProcess(args[1], args[2], args[3], args[4]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// writerProcess opens its own ChainedWriter on path, says it is ready, waits
// for the go signal in dir, and appends each events as writer w.
func writerProcess(path, writer, count, dir string) error {
	w, err := strconv.Atoi(writer)
	if err != nil {
		return err
	}
	each, err := strconv.Atoi(count)
	if err != nil {
		return err
	}
	cw, err := NewChainedWriter(path)
	if err != nil {
		return err
	}
	defer cw.Close()
	if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("ready-%d", w)), nil, 0o644); err != nil {
		return err
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("writer %d: no go signal", w)
		}
		time.Sleep(time.Millisecond)
	}
	for i := range each {
		if err := cw.Write(writerEvent(w, i, (i*37)%300)); err != nil {
			return fmt.Errorf("writer %d event %d: %w", w, i, err)
		}
	}
	return nil
}

// Four processes, each with its own ChainedWriter on one file, released at
// once: the production shape, where a pod being replaced and its successor,
// or a service and its CronJob, append to one stream.
func TestConcurrentProcessesOnOneFileKeepOneChain(t *testing.T) {
	const procs, each = 4, 200
	dir := t.TempDir()
	path := filepath.Join(dir, "bus.ndjson")

	cmds := make([]*exec.Cmd, procs)
	outs := make([]bytes.Buffer, procs)
	for w := range cmds {
		cmd := exec.Command(os.Args[0], "--", helperMarker, path, strconv.Itoa(w), strconv.Itoa(each), dir)
		cmd.Stdout, cmd.Stderr = &outs[w], &outs[w]
		if err := cmd.Start(); err != nil {
			t.Fatalf("start helper %d: %v", w, err)
		}
		cmds[w] = cmd
	}
	deadline := time.Now().Add(30 * time.Second)
	for w := 0; w < procs; {
		if _, err := os.Stat(filepath.Join(dir, fmt.Sprintf("ready-%d", w))); err == nil {
			w++
			continue
		}
		if time.Now().After(deadline) {
			t.Fatalf("helper %d never became ready", w)
		}
		time.Sleep(time.Millisecond)
	}
	if err := os.WriteFile(filepath.Join(dir, "go"), nil, 0o644); err != nil {
		t.Fatalf("go: %v", err)
	}
	for w, cmd := range cmds {
		if err := cmd.Wait(); err != nil {
			t.Fatalf("helper %d: %v\n%s", w, err, outs[w].String())
		}
	}
	assertOneChain(t, path, procs*each)
	assertEveryWriterComplete(t, path, procs, each)
}

// While another open file holds the lock, Write waits; and the tail it chains
// from is the one on disk AFTER it got the lock, here a line the holder
// appended while Write was waiting.
func TestAWriteWaitsForTheFileLockAndReadsTheTailAfterIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bus.ndjson")
	first := mustWriter(t, path)
	if err := first.Write(writerEvent(0, 0, 0)); err != nil {
		t.Fatalf("write: %v", err)
	}
	waiting := mustWriter(t, path)

	holder, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		t.Fatalf("open holder: %v", err)
	}
	defer holder.Close()
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatalf("hold the lock: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- waiting.Write(writerEvent(2, 0, 0)) }()
	select {
	case err := <-done:
		t.Fatalf("Write returned (%v) while another open file held the lock", err)
	case <-time.After(300 * time.Millisecond):
	}

	// The holder appends a correctly chained line of its own.
	lines := fileLines(t, path)
	prev, err := ChainHashRaw(lines[len(lines)-1])
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	foreign := writerEvent(1, 0, 0)
	foreign.PrevHash = prev
	data, err := Marshal(foreign)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := holder.Write(append(data, '\n')); err != nil {
		t.Fatalf("holder write: %v", err)
	}
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatalf("release: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Write after the lock was released: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("Write never took the released lock")
	}
	assertOneChain(t, path, 3)
}

// The lock is still held at the moment the line is appended, and released
// once Write returns. A probe from another open file must be refused at the
// first point and granted at the second.
func TestTheFileLockIsHeldWhileTheLineIsAppended(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bus.ndjson")
	cw := mustWriter(t, path)
	if err := cw.Write(writerEvent(0, 0, 0)); err != nil {
		t.Fatalf("write: %v", err)
	}

	var probes []error
	testHookBeforeAppend = func() { probes = append(probes, tryLock(t, path)) }
	t.Cleanup(func() { testHookBeforeAppend = func() {} })

	if err := cw.Write(writerEvent(0, 1, 0)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(probes) != 1 {
		t.Fatalf("the hook before the append ran %d times, want 1", len(probes))
	}
	if !errors.Is(probes[0], syscall.EWOULDBLOCK) {
		t.Fatalf("another open file could lock the file while the line was being appended (probe: %v)", probes[0])
	}
	if err := tryLock(t, path); err != nil {
		t.Fatalf("the lock is still held after Write returned: %v", err)
	}
	assertOneChain(t, path, 2)
}

// panicky panics when it is marshaled, which encoding/json passes through.
type panicky struct{}

func (panicky) MarshalJSON() ([]byte, error) { panic("marshal panicked") }

// A panic while appending must not leave the file locked. A caller that
// recovers (net/http does, per request) would otherwise go on holding the
// lock, and every writer of the file would wait on it for good.
func TestAPanicWhileAppendingStillReleasesTheLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bus.ndjson")
	cw := mustWriter(t, path)

	e := writerEvent(0, 0, 0)
	e.Data["bad"] = panicky{}
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatalf("expected the marshal panic to reach the caller")
			}
		}()
		cw.Write(e)
	}()

	if err := tryLock(t, path); err != nil {
		t.Fatalf("the file is still locked after a panic in Write: %v", err)
	}
	if err := cw.Write(writerEvent(0, 1, 0)); err != nil {
		t.Fatalf("the writer is unusable after a recovered panic: %v", err)
	}
	assertOneChain(t, path, 1)
}
