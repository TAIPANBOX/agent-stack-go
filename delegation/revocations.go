package delegation

// The revocation list, held locally, that [Options.Revoked] is meant to be
// filled from.
//
// # What was wrong before this file
//
// vouchryx has served `GET /v1/revocations` since the day it was written, with
// an `as_of` cursor put there so a poller could tell an empty list from a
// failed fetch. Measured 2026-08-26: nothing polled it. No consumer of this
// module set [Options.Revoked], and tokenfuse's two doors passed a closure that
// answers false. Meanwhile this module's own README said "every enforcement
// point checks with it" in the present tense, and three vouchryx documents said
// the same. This is the half that makes those sentences true.
//
// # The fetch is out of band and the check is local, which is invariant 15 intact
//
// [Revocations.Check] takes no context and returns no error, so it cannot block
// and has nowhere to send a request; the network lives in [Fetch] and
// [Revocations.Refresh], which take a context because they can. That is the
// seam, and it is a shape rather than a promise: a method with no context and
// no error is one the compiler will not let become a round trip.
//
// A poller calls Refresh on its own schedule. A poll that hangs costs the
// request path nothing but age, and age is the whole of the design below.
//
// # Age is the third state, and it is the useful one
//
// The estate has answered "what happens when a dependency is unreachable"
// twice, the same way both times: an operator-chosen fail mode, open or closed,
// defaulting to open (tokenfuse's `wardryx.FailMode` and
// `TOKENFUSE_MCP_TAINT_FAILMODE`). [FailMode] here is the same word with the
// same default, so the estate does not answer one question two ways.
//
// What a revocation list adds is that a stale list is still mostly right. A PDP
// you cannot reach tells you nothing at all; a list from four minutes ago still
// holds every revocation older than four minutes.
//
// # So the maximum age governs a MISS and never a HIT
//
// A hit is data: this list said this token was revoked, and nothing un-revokes
// a token, so the answer does not rot. Throwing away a revocation we hold
// because the list got old takes a token we KNOW is dead and calls it live,
// which is worse than the outage it was reacting to.
//
// A miss is not data. It is an inference from the list being COMPLETE, and
// completeness is exactly the property that expires. A miss on a fresh list
// means "not revoked"; a miss on a stale list means "I do not know", and that
// is the question the fail mode is asked.
//
// # Never fetched is not stale
//
// Both defer to the fail mode and they are different facts, so [Basis] keeps
// them apart. Nothing fetched means the poller was never wired or has never
// once succeeded: a configuration fault, which does not clear itself and which
// nothing else in the estate will mention. Stale means a poller that was
// working stopped, which usually clears.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// DefaultRevocationMaxAge is how old a held list may be and still answer that a
// token is absent from it.
//
// # Why one minute, which is the window in which a revoked token still works
//
// Not the window in the healthy case: there it is the poll interval. This is
// how long a consumer may go on trusting an unrefreshed list once the poller
// has stopped, before a miss stops meaning "not revoked".
//
// The bound comes from the token rather than from taste. vouchryx mints at a
// five-minute default TTL and refuses a TTL over an hour. A list allowed to
// outlive a token means one minted after the last successful poll can be
// revoked and go on working for its whole life, and the control was decorative
// for a whole generation of tokens rather than merely late. A minute is a fifth
// of the default TTL.
//
// It is a default and not a law. What it must not be is unstated, because the
// number IS the claim that revoking ends the right to act.
const DefaultRevocationMaxAge = time.Minute

// MaxSnapshotBytes caps a fetched body. The list comes off somebody else's
// wire, and this is a poller that runs for the life of the process.
const MaxSnapshotBytes = 4 << 20

// Refusals [Revocations.Install] can give. Both keep the list already held.
var (
	// ErrCursorWentBackwards is a snapshot describing an EARLIER moment than
	// the one held: a restarted instance, a second one behind a load balancer,
	// or a clock. Refused rather than taken, and the reason is the age rather
	// than the entries. Installing it would reset the age, so a view that had
	// genuinely stopped moving would start reading as fresh, and the age is
	// what every other rule here rests on.
	ErrCursorWentBackwards = errors.New("delegation: the revocation list describes an earlier moment than the one held")
	// ErrNoCursor is a snapshot with no `as_of` at all, which can neither be
	// compared with the one held nor aged.
	ErrNoCursor = errors.New("delegation: the revocation list carries no as_of cursor")
)

// Revocation is one entry, in the shape vouchryx serves it.
//
// The JSON names match `internal/revoke.Entry` exactly, because this is a wire
// type and a rename here is a consumer that silently stops matching.
type Revocation struct {
	// JTI revokes exactly one token. Empty when this is a subject entry.
	JTI string `json:"jti,omitempty"`
	// Subject revokes every token issued for it at or before IssuedBefore.
	Subject string `json:"subject,omitempty"`
	// IssuedBefore is a Unix second. Only meaningful with Subject.
	IssuedBefore int64 `json:"issued_before,omitempty"`
	// Expires is when this entry stops being load-bearing: the last moment a
	// token it could match might still be valid.
	//
	// Zero means the producer stated none, and such an entry is KEPT rather
	// than dropped. The two mistakes are different sizes: dropping an entry
	// early makes a revoked token work, and keeping one late only outlives a
	// token that has expired anyway.
	Expires int64 `json:"expires,omitempty"`
}

// covers reports whether this entry covers a token.
//
// An entry naming neither a token nor a subject matches nothing. Not defensive
// programming for its own sake: comparing two empty ids matches every token
// that carries none, and a producer other than vouchryx is not bound by
// vouchryx's own refusal to record one.
func (e Revocation) covers(jti, subject string, issuedAt int64) bool {
	if e.JTI != "" && e.JTI == jti {
		return true
	}
	// At or before, never strictly before: the second a revocation happens in
	// is the second an incident happens in, and vouchryx records the cursor
	// with the same rule at the other end.
	return e.Subject != "" && e.Subject == subject && issuedAt <= e.IssuedBefore
}

func (e Revocation) liveAt(now time.Time) bool {
	return e.Expires == 0 || e.Expires > now.Unix()
}

// Snapshot is one fetched list, with the cursor saying which moment it
// describes.
//
// AsOf is why this is a struct rather than a slice. An empty list and a fetch
// that failed are the same bytes without it, and one of those two means every
// revoked token in the estate is live again.
type Snapshot struct {
	Revocations []Revocation `json:"revocations"`
	AsOf        int64        `json:"as_of"`
}

// ParseSnapshot reads the body of `GET /v1/revocations`.
//
// It refuses a body that is not a JSON object, which is what a proxy in the
// way, a wrong route, or a second service on the port produces. Unknown MEMBERS
// are accepted on purpose: entries carry `actor` and `reason` this consumer has
// no use for, and refusing a member vouchryx adds later would make every
// consumer a release blocker.
func ParseSnapshot(raw []byte) (Snapshot, error) {
	var probe any
	if err := json.Unmarshal(raw, &probe); err != nil {
		return Snapshot{}, fmt.Errorf("delegation: revocation list is not JSON: %w", err)
	}
	if _, ok := probe.(map[string]any); !ok {
		return Snapshot{}, errors.New("delegation: a revocations body is a JSON object with revocations and as_of")
	}
	var s Snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return Snapshot{}, fmt.Errorf("delegation: revocation list has the wrong shape: %w", err)
	}
	return s, nil
}

// FailMode is what an unanswerable miss means, chosen by the operator.
type FailMode int

const (
	// FailOpen lets a call through when the list is too old to answer a miss.
	// The zero value and the default, because it is what every deployment does
	// today: nothing polls, so nothing is refused, and an addition that starts
	// refusing traffic on upgrade is a breaking change wearing a security
	// fix's clothes.
	FailOpen FailMode = iota
	// FailClosed refuses when the list is too old to answer a miss, for a
	// deployment that has decided an unverifiable delegation is not one it
	// will honour.
	FailClosed
)

func (f FailMode) refuses() bool { return f == FailClosed }

func (f FailMode) String() string {
	if f == FailClosed {
		return "closed"
	}
	return "open"
}

// Basis is where an [Answer] came from. The verdict alone is not enough to log
// honestly: false from a fresh list and false from a fail mode are the same bit
// and different facts.
type Basis int

const (
	// BasisListed means an entry matched. The age is reported and is NOT part
	// of that decision.
	BasisListed Basis = iota
	// BasisAbsent means nothing matched and the list is young enough for that
	// to mean something.
	BasisAbsent
	// BasisStale means nothing matched and the list is older than the maximum,
	// so the fail mode answered instead.
	BasisStale
	// BasisNever means no list has ever been installed, so the fail mode
	// answered. A different fact from BasisStale and worth a different log
	// line: a poller that has never once succeeded does not fix itself.
	BasisNever
)

func (b Basis) String() string {
	switch b {
	case BasisListed:
		return "listed"
	case BasisAbsent:
		return "absent"
	case BasisStale:
		return "stale"
	case BasisNever:
		return "never-fetched"
	}
	return "unknown"
}

// IsFallback reports whether the fail mode answered rather than the list. The
// member a caller must not skip when deciding whether to record something.
func (b Basis) IsFallback() bool { return b == BasisStale || b == BasisNever }

// Answer is one revocation verdict and where it came from.
type Answer struct {
	Revoked bool
	Basis   Basis
	// Age of the list this answer came from. Meaningless, and zero, when Basis
	// is BasisNever: there was no list.
	Age time.Duration
}

// Revocations is the last-known-good revocation list plus the policy for what
// its age means.
//
// Safe for concurrent use: a poller writes while request paths read.
type Revocations struct {
	maxAge   time.Duration
	failMode FailMode

	mu   sync.RWMutex
	held *Snapshot
	// fetchedAt is OUR clock when the held list was installed. Age is measured
	// from it rather than from AsOf because what this bounds is the interval
	// since this process last synchronised, which is a fact about us. AsOf is
	// kept beside it for the ordering rule and for an operator reading skew.
	fetchedAt         time.Time
	rejectedBackwards uint64
}

// NewRevocations builds a cache with an operator's policy. A maxAge of zero or
// less takes [DefaultRevocationMaxAge]; a deployment that wants only hits to
// count sets a negative one deliberately through [Revocations.SetMaxAge].
func NewRevocations(maxAge time.Duration, failMode FailMode) *Revocations {
	if maxAge <= 0 {
		maxAge = DefaultRevocationMaxAge
	}
	return &Revocations{maxAge: maxAge, failMode: failMode}
}

// SetMaxAge overrides the maximum, including with zero or a negative value,
// which means every list is stale the instant it lands and only a hit counts.
// Separate from the constructor so that configuration is a decision rather than
// something a zero value falls into.
func (r *Revocations) SetMaxAge(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.maxAge = d
}

// Install offers a freshly fetched snapshot. On refusal the list already held
// is kept, unchanged, and so is its age.
func (r *Revocations) Install(s Snapshot, now time.Time) error {
	if s.AsOf <= 0 {
		return ErrNoCursor
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.held != nil && s.AsOf < r.held.AsOf {
		r.rejectedBackwards++
		return fmt.Errorf("%w: holding %d, offered %d", ErrCursorWentBackwards, r.held.AsOf, s.AsOf)
	}
	// Equal cursors ARE accepted. AsOf is a Unix second, so two polls inside
	// one second legitimately carry the same value and refusing that would
	// break any poller faster than 1 Hz.
	r.held = &s
	r.fetchedAt = now
	return nil
}

// Check reports whether a token is revoked, and on what basis.
//
// No context and no error, by construction. That shape is the invariant rather
// than a convenience: it is what makes a revocation check something a request
// path can afford on every call, and what stops this from quietly becoming a
// round trip to the token service.
func (r *Revocations) Check(jti, subject string, issuedAt int64, now time.Time) Answer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.held == nil {
		return Answer{Revoked: r.failMode.refuses(), Basis: BasisNever}
	}
	age := now.Sub(r.fetchedAt)

	for _, e := range r.held.Revocations {
		if e.liveAt(now) && e.covers(jti, subject, issuedAt) {
			// A hit, whatever the age. Nothing un-revokes a token, so this
			// answer does not rot, and dropping it because the list got old
			// would call a token we know is dead a live one.
			return Answer{Revoked: true, Basis: BasisListed, Age: age}
		}
	}

	if age <= r.maxAge {
		return Answer{Revoked: false, Basis: BasisAbsent, Age: age}
	}
	return Answer{Revoked: r.failMode.refuses(), Basis: BasisStale, Age: age}
}

// Hook is the closure [Options.Revoked] takes, bound to one request's clock.
//
//	o.Revoked = revs.Hook(o.Now, func(a delegation.Answer) { ... })
//
// observe takes the whole [Answer] and may be nil. It is a parameter rather
// than something a caller has to go and ask for, so the site that wires this up
// has to decide what it does with a fallback rather than never being shown one.
func (r *Revocations) Hook(now time.Time, observe func(Answer)) func(jti, subject string, issuedAt int64) bool {
	return func(jti, subject string, issuedAt int64) bool {
		a := r.Check(jti, subject, issuedAt, now)
		if observe != nil {
			observe(a)
		}
		return a.Revoked
	}
}

// Age reports how old the held list is. The second result is false when nothing
// has ever been installed, which is a different fact from an age of zero.
func (r *Revocations) Age(now time.Time) (time.Duration, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.held == nil {
		return 0, false
	}
	return now.Sub(r.fetchedAt), true
}

// AsOf reports the cursor of the held list.
func (r *Revocations) AsOf() (int64, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.held == nil {
		return 0, false
	}
	return r.held.AsOf, true
}

// RejectedBackwards counts snapshots refused for describing an earlier moment
// than the one held. Not zero means something is serving from behind.
func (r *Revocations) RejectedBackwards() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.rejectedBackwards
}

// Fetch retrieves one snapshot from vouchryx's `GET /v1/revocations`.
//
// It takes a context because it can block, which is the seam: nothing on the
// request path here takes one. A nil client takes [http.DefaultClient], and a
// caller that cares about its own deadlines passes one with a timeout.
func Fetch(ctx context.Context, c *http.Client, url string) (Snapshot, error) {
	if c == nil {
		c = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Snapshot{}, fmt.Errorf("delegation: revocation fetch: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return Snapshot{}, fmt.Errorf("delegation: revocation fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// A non-200 is not an empty list. Saying so is the whole reason this
		// returns an error rather than a zero Snapshot: the caller must not be
		// able to install "nothing is revoked" by accident.
		return Snapshot{}, fmt.Errorf("delegation: revocation fetch: %s answered %d", url, resp.StatusCode)
	}
	// Capped, because the list comes off somebody else's wire and this runs for
	// the life of the process. One byte over the cap is refused rather than
	// truncated: a truncated JSON body does not parse, but a truncated one that
	// happened to parse would be a SHORTER revocation list, which is the
	// direction that lets a revoked token work.
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxSnapshotBytes+1))
	if err != nil {
		return Snapshot{}, fmt.Errorf("delegation: revocation fetch: %w", err)
	}
	if len(body) > MaxSnapshotBytes {
		return Snapshot{}, fmt.Errorf("delegation: revocation list is over %d bytes", MaxSnapshotBytes)
	}
	return ParseSnapshot(body)
}

// Refresh fetches and installs, for a poller's loop. The one call that reaches
// the network on behalf of this type, and it takes a context to say so.
func (r *Revocations) Refresh(ctx context.Context, c *http.Client, url string, now time.Time) error {
	s, err := Fetch(ctx, c, url)
	if err != nil {
		// The held list is untouched and goes on ageing, which is the point:
		// a failed poll is not an empty list, and the age is what eventually
		// turns that into the operator's fail mode.
		return err
	}
	return r.Install(s, now)
}
