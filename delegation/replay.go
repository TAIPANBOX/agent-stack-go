package delegation

import (
	"math"
	"sync"
	"time"
)

// replayGeneration is how long one generation of a [ReplayCache] lasts: twice
// [Window], and that is not a safety margin. A proof's `iat` is accepted up to
// a window either side of now, so the longest interval over which one proof can
// be presented twice and be fresh both times is two windows. Rotating every
// window would keep between one and two windows of history, and the shortfall
// would be a replay that works.
const replayGeneration = 2 * Window

// ReplayCache remembers which proof `jti` values have been seen, so a proof is
// single use at every door of a process that shares one cache. It is
// tokenfuse's `ReplayCache` (crates/dpop), rule for rule, and the shared
// agent-token table runs both against the same sequences.
//
// # Why a proof needs this at all
//
// `htm` and `htu` pin a proof to one method and one URL, which is most of the
// value when an API has many endpoints and nearly none when it has one: a door
// that answers every call as a POST to a single path would otherwise take a
// proof captured from a harmless call as a credential for any other call, for
// the rest of the window.
//
// # Two generations
//
// Nothing is scanned or evicted per entry. Two sets are kept; when the current
// one is a generation old it becomes the previous one and a fresh set starts. A
// lookup consults both, so memory is bounded by traffic rather than by a timer,
// and no entry is forgotten while a proof carrying it could still be fresh.
//
// # Where it says nothing
//
// It is per PROCESS and in memory. Two doors behind a load balancer each
// remember their own, so a proof used at one can be replayed once at the other,
// and a restart forgets everything for one generation. Closing either needs
// shared state, which is a deployment decision rather than a type.
type ReplayCache struct {
	cap int

	mu       sync.Mutex
	begun    bool
	started  int64
	current  map[string]struct{}
	previous map[string]struct{}
}

// NewReplayCache returns an empty cache. `cap` bounds ONE generation, so at
// most twice `cap` identifiers are held, and a generation at its cap refuses a
// new `jti` rather than forgetting an old one.
func NewReplayCache(cap int) *ReplayCache {
	return &ReplayCache{
		cap:      cap,
		current:  make(map[string]struct{}),
		previous: make(map[string]struct{}),
	}
}

// CheckAndRecord records `jti` as used at `now`, or says why it may not be:
// [ErrReplay] for a `jti` seen inside the window, [ErrReplayCacheFull] when the
// current generation is at its cap. The clock is read in whole seconds.
func (c *ReplayCache) CheckAndRecord(jti string, now time.Time) error {
	sec := now.Unix()
	gen := int64(replayGeneration / time.Second)
	c.mu.Lock()
	defer c.mu.Unlock()
	// `started` moves forward only. A clock that steps backwards must not
	// rotate the generations, or whoever can nudge it forwards and back gets
	// two rotations and an empty cache.
	if !c.begun || saturatingSub(sec, c.started) >= gen {
		if !c.begun || saturatingSub(sec, c.started) >= 2*gen {
			// Two generations or more since the last rotation: everything held
			// is older than any proof that could still be fresh.
			c.previous = make(map[string]struct{})
		} else {
			c.previous = c.current
		}
		c.current = make(map[string]struct{})
		c.started = sec
		c.begun = true
	}
	if _, seen := c.current[jti]; seen {
		return ErrReplay
	}
	if _, seen := c.previous[jti]; seen {
		return ErrReplay
	}
	if len(c.current) >= c.cap {
		// Refused rather than forgetting one: forgetting under pressure is a
		// replay guard that stops guarding exactly when somebody is pushing.
		return ErrReplayCacheFull
	}
	c.current[jti] = struct{}{}
	return nil
}

// saturatingSub is a - b without wrapping, as Rust's saturating_sub, so an
// absurd clock reads as far in the future or the past rather than as its
// opposite.
func saturatingSub(a, b int64) int64 {
	d := a - b
	if (b < 0 && d < a) || (b > 0 && d > a) {
		if b < 0 {
			return math.MaxInt64
		}
		return math.MinInt64
	}
	return d
}
