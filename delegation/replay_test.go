package delegation

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// The replay cache, held as tests. Each is tokenfuse's `crates/dpop` test of
// the same name, so the two caches are asked the same questions; the shared
// table asks them again as data.

func at(sec int64) time.Time { return time.Unix(sec, 0) }

func TestASecondUseOfOneJtiIsRefused(t *testing.T) {
	c := NewReplayCache(16)
	if err := c.CheckAndRecord("j1", at(1_000)); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := c.CheckAndRecord("j1", at(1_000)); !errors.Is(err, ErrReplay) {
		t.Fatalf("second use at the same moment: %v", err)
	}
	if err := c.CheckAndRecord("j1", at(1_010)); !errors.Is(err, ErrReplay) {
		t.Fatalf("second use ten seconds later, still the same window: %v", err)
	}
}

// The negative control. A cache that refused everything would pass the test
// above, and would take every door with it.
func TestDistinctJtisAreAllAdmitted(t *testing.T) {
	c := NewReplayCache(16)
	for i := 0; i < 10; i++ {
		if err := c.CheckAndRecord(fmt.Sprintf("j%d", i), at(1_000)); err != nil {
			t.Fatalf("j%d: %v", i, err)
		}
	}
}

// A jti is forgotten only once no proof carrying it could still be fresh,
// which is why a generation is two windows rather than one: a proof's iat may
// sit a window ahead of now, and now a window past iat. The pairing is
// load-bearing, forgetting is safe BECAUSE a stale proof is refused, so the
// test states the coupling rather than assuming it. The second half is the
// rotation boundary, where a jti recorded in the last second of a generation
// must outlive the whole of the next one.
func TestAJtiSurvivesEveryMomentAProofCarryingItCouldStillBeFresh(t *testing.T) {
	c := NewReplayCache(16)
	t0 := int64(1_000_000)
	win := int64(Window / time.Second)
	if err := c.CheckAndRecord("j1", at(t0)); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckAndRecord("j1", at(t0+2*win)); !errors.Is(err, ErrReplay) {
		t.Fatalf("forgotten while a replay of it would still verify: %v", err)
	}
	if err := c.CheckAndRecord("j1", at(t0+8*win)); err != nil {
		t.Fatalf("long past any freshness the identifier is no longer worth memory: %v", err)
	}

	c = NewReplayCache(16)
	gen := int64(replayGeneration / time.Second)
	if err := c.CheckAndRecord("j0", at(t0)); err != nil {
		t.Fatal(err)
	}
	last := t0 + gen - 1
	if err := c.CheckAndRecord("late", at(last)); err != nil {
		t.Fatal(err)
	}
	for _, s := range []int64{last + 1, last + win, last + 2*win} {
		if err := c.CheckAndRecord("late", at(s)); !errors.Is(err, ErrReplay) {
			t.Fatalf("a jti recorded at %d forgotten at %d, %d s later: %v", last, s, s-last, err)
		}
	}
}

// At the cap it refuses rather than forgetting. Forgetting under pressure is a
// replay guard that stops guarding exactly when somebody is pushing on it.
func TestAFullCacheRefusesRatherThanForgetting(t *testing.T) {
	c := NewReplayCache(2)
	for _, j := range []string{"j1", "j2"} {
		if err := c.CheckAndRecord(j, at(1_000)); err != nil {
			t.Fatalf("%s: %v", j, err)
		}
	}
	if err := c.CheckAndRecord("j3", at(1_000)); !errors.Is(err, ErrReplayCacheFull) {
		t.Fatalf("a third jti in a cache of two: %v", err)
	}
	if err := c.CheckAndRecord("j1", at(1_000)); !errors.Is(err, ErrReplay) {
		t.Fatalf("a full cache still answers about what it remembers: %v", err)
	}
	// A full generation rotates like any other: the cap bounds memory, it does
	// not end the cache.
	gen := int64(replayGeneration / time.Second)
	if err := c.CheckAndRecord("j3", at(1_000+gen)); err != nil {
		t.Fatalf("after a rotation there is room again: %v", err)
	}
	if err := c.CheckAndRecord("j1", at(1_000+gen)); !errors.Is(err, ErrReplay) {
		t.Fatalf("the previous generation is still consulted: %v", err)
	}
}

// A clock that steps backwards must not rotate the generations: two rotations
// is an empty cache, and somebody who can nudge a clock would get one.
func TestAClockThatWalksBackwardsDoesNotEmptyTheCache(t *testing.T) {
	c := NewReplayCache(16)
	win := int64(Window / time.Second)
	if err := c.CheckAndRecord("j1", at(1_000_000)); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckAndRecord("j1", at(1_000_000-10*win)); !errors.Is(err, ErrReplay) {
		t.Fatalf("ten windows back: %v", err)
	}
	// Back, then forward again by less than a generation from the start: still
	// one generation, nothing rotated.
	if err := c.CheckAndRecord("j1", at(1_000_000+win)); !errors.Is(err, ErrReplay) {
		t.Fatalf("forward again: %v", err)
	}
}
