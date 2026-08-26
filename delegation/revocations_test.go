package delegation

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

var revNow = time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)

func revJTI(id string, expires time.Time) Revocation {
	return Revocation{JTI: id, Expires: expires.Unix()}
}

// holdingOne is a cache that fetched, at revNow, a list naming one token.
func holdingOne(t *testing.T) *Revocations {
	t.Helper()
	r := NewRevocations(0, FailOpen)
	s := Snapshot{
		AsOf:        revNow.Unix(),
		Revocations: []Revocation{revJTI("tok-1", revNow.Add(time.Hour))},
	}
	if err := r.Install(s, revNow); err != nil {
		t.Fatalf("install: %v", err)
	}
	return r
}

// THE ONE THE WHOLE THING IS FOR. No consumer of this module has ever set
// Options.Revoked, so this is an answer nothing in the estate has given.
func TestARevokedTokenIsRefusedBySomethingThatActuallyReadTheList(t *testing.T) {
	a := holdingOne(t).Check("tok-1", "user://acme/alice", revNow.Add(-time.Minute).Unix(), revNow)
	if !a.Revoked {
		t.Fatalf("the list names tok-1 and this answered %+v", a)
	}
	if a.Basis != BasisListed {
		t.Fatalf("basis: %v", a.Basis)
	}
}

// The negative control. A cache that refused everything would pass the test
// above and be worth nothing.
func TestATokenTheListDoesNotNameIsNotRefused(t *testing.T) {
	a := holdingOne(t).Check("tok-2", "user://acme/alice", revNow.Add(-time.Minute).Unix(), revNow)
	if a.Revoked || a.Basis != BasisAbsent {
		t.Fatalf("a token nobody revoked: %+v", a)
	}
}

func TestASubjectRevocationCoversWhatWasIssuedAtOrBeforeItsMoment(t *testing.T) {
	r := NewRevocations(0, FailOpen)
	err := r.Install(Snapshot{
		AsOf: revNow.Unix(),
		Revocations: []Revocation{{
			Subject:      "agent://acme/triage",
			IssuedBefore: revNow.Unix(),
			Expires:      revNow.Add(time.Hour).Unix(),
		}},
	}, revNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		issuedAt int64
		want     bool
		why      string
	}{
		{revNow.Add(-time.Minute).Unix(), true, "issued before the revocation"},
		{revNow.Unix(), true, "issued in the very second of it"},
		{revNow.Add(time.Second).Unix(), false, "issued after it: revoking is not banning"},
	} {
		if got := r.Check("tok-9", "agent://acme/triage", c.issuedAt, revNow); got.Revoked != c.want {
			t.Fatalf("%s: got %+v", c.why, got)
		}
	}
}

// The substance. A list from four minutes ago still holds every revocation
// older than four minutes, and answering false here would take a token this
// process KNOWS is dead and call it live.
func TestAStaleListStillRefusesWhatItNames(t *testing.T) {
	late := revNow.Add(4 * DefaultRevocationMaxAge)
	a := holdingOne(t).Check("tok-1", "user://acme/alice", revNow.Add(-time.Minute).Unix(), late)
	if !a.Revoked {
		t.Fatalf("age decides what a MISS means and never what a HIT means: %+v", a)
	}
	if a.Basis != BasisListed || a.Age != 4*DefaultRevocationMaxAge {
		t.Fatalf("and it says how old the list it matched in was: %+v", a)
	}
}

// The case a naive implementation gets wrong by serving for ever.
func TestAMissOnAStaleListFallsBackToTheFailMode(t *testing.T) {
	for _, c := range []struct {
		mode FailMode
		want bool
	}{{FailOpen, false}, {FailClosed, true}} {
		r := NewRevocations(0, c.mode)
		if err := r.Install(Snapshot{AsOf: revNow.Unix()}, revNow); err != nil {
			t.Fatal(err)
		}
		late := revNow.Add(DefaultRevocationMaxAge + time.Second)
		got := r.Check("tok-2", "user://acme/alice", revNow.Unix(), late)
		if got.Revoked != c.want || got.Basis != BasisStale {
			t.Fatalf("fail %v past the maximum age: %+v", c.mode, got)
		}
	}
}

// The boundary in the other direction, so "stale" cannot quietly become
// "anything that is not this instant".
func TestAListExactlyAtTheMaximumAgeIsStillTrustedForAMiss(t *testing.T) {
	at := revNow.Add(DefaultRevocationMaxAge)
	got := holdingOne(t).Check("tok-2", "user://acme/alice", revNow.Unix(), at)
	if got.Revoked || got.Basis != BasisAbsent {
		t.Fatalf("exactly at the maximum: %+v", got)
	}
}

// Never fetched is not stale. Both defer to the fail mode and they are
// different faults: one is an outage, the other is a poller nobody wired.
func TestAListNobodyEverFetchedSaysSoRatherThanReadingAsEmpty(t *testing.T) {
	for _, c := range []struct {
		mode FailMode
		want bool
	}{{FailOpen, false}, {FailClosed, true}} {
		got := NewRevocations(0, c.mode).Check("tok-1", "user://acme/alice", revNow.Unix(), revNow)
		if got.Revoked != c.want || got.Basis != BasisNever {
			t.Fatalf("fail %v with nothing ever fetched: %+v", c.mode, got)
		}
		if !got.Basis.IsFallback() {
			t.Fatal("a never-fetched answer is a fallback")
		}
		if _, ok := NewRevocations(0, c.mode).Age(revNow); ok {
			t.Fatal("an age was reported for a list that does not exist")
		}
	}
}

func TestAnAnswerFromTheListIsNeverReportedAsAFallback(t *testing.T) {
	r := holdingOne(t)
	for _, id := range []string{"tok-1", "tok-2"} {
		if got := r.Check(id, "user://acme/alice", revNow.Unix(), revNow); got.Basis.IsFallback() {
			t.Fatalf("%s was answered from the list: %+v", id, got)
		}
	}
}

// An older snapshot never replaces a newer one, and the reason is the age
// rather than the entries: installing it would reset the clock and a view that
// had stopped moving would start reading as fresh.
func TestACursorThatMovedBackwardsIsRefusedAndDoesNotResetTheAge(t *testing.T) {
	r := holdingOne(t)
	later := revNow.Add(30 * time.Second)
	err := r.Install(Snapshot{AsOf: revNow.Add(-5 * time.Second).Unix()}, later)
	if !errors.Is(err, ErrCursorWentBackwards) {
		t.Fatalf("a backwards cursor was accepted: %v", err)
	}
	if r.RejectedBackwards() != 1 {
		t.Fatalf("rejected: %d", r.RejectedBackwards())
	}
	if got, _ := r.AsOf(); got != revNow.Unix() {
		t.Fatalf("the newer list was replaced: as_of %d", got)
	}
	if age, _ := r.Age(later); age != 30*time.Second {
		t.Fatalf("the age was reset to %v rather than staying 30s", age)
	}
	if !r.Check("tok-1", "user://acme/alice", revNow.Unix(), later).Revoked {
		t.Fatal("the refused snapshot was empty, and it must not have emptied this")
	}
}

func TestACursorThatDidNotMoveIsAcceptedBecauseASecondIsACoarseClock(t *testing.T) {
	r := holdingOne(t)
	if err := r.Install(Snapshot{AsOf: revNow.Unix()}, revNow.Add(time.Second)); err != nil {
		t.Fatalf("an equal cursor was refused, which breaks any poller faster than 1 Hz: %v", err)
	}
	if r.RejectedBackwards() != 0 {
		t.Fatal("an equal cursor was counted as backwards")
	}
	if r.Check("tok-1", "user://acme/alice", revNow.Unix(), revNow.Add(time.Second)).Revoked {
		t.Fatal("the same cursor with an empty list is a list that emptied, and it applies")
	}
}

func TestASnapshotWithNoCursorIsRefusedRatherThanAgedFromNothing(t *testing.T) {
	r := NewRevocations(0, FailOpen)
	s := Snapshot{Revocations: []Revocation{revJTI("tok-1", revNow.Add(time.Hour))}}
	if err := r.Install(s, revNow); !errors.Is(err, ErrNoCursor) {
		t.Fatalf("a cursorless list was installed: %v", err)
	}
	if got := r.Check("tok-1", "user://acme/alice", revNow.Unix(), revNow); got.Basis != BasisNever {
		t.Fatalf("a refused snapshot must leave this having never fetched: %+v", got)
	}
}

// Hostile shape: comparing two empty ids matches every token that carries none,
// and this list comes off somebody else's wire.
func TestAnEntryNamingNeitherATokenNorASubjectMatchesNothing(t *testing.T) {
	r := NewRevocations(0, FailOpen)
	err := r.Install(Snapshot{
		AsOf:        revNow.Unix(),
		Revocations: []Revocation{{Expires: revNow.Add(time.Hour).Unix()}},
	}, revNow)
	if err != nil {
		t.Fatal(err)
	}
	if r.Check("", "", 0, revNow).Revoked {
		t.Fatal("an entry naming nothing revoked a token naming nothing")
	}
	if r.Check("tok-1", "user://acme/alice", revNow.Unix(), revNow).Revoked {
		t.Fatal("an entry naming nothing revoked an ordinary token")
	}
}

func TestAnEntryPastItsOwnExpiryStopsMatching(t *testing.T) {
	r := NewRevocations(0, FailOpen)
	if err := r.Install(Snapshot{
		AsOf:        revNow.Unix(),
		Revocations: []Revocation{revJTI("tok-1", revNow.Add(10*time.Second))},
	}, revNow); err != nil {
		t.Fatal(err)
	}
	if !r.Check("tok-1", "s", 0, revNow.Add(9*time.Second)).Revoked {
		t.Fatal("an entry stopped matching before its own expiry")
	}
	if r.Check("tok-1", "s", 0, revNow.Add(10*time.Second)).Revoked {
		t.Fatal("an entry only outlives the last token it could match")
	}
}

// The two mistakes are different sizes. Dropping early makes a revoked token
// work; keeping late outlives a token that has expired anyway.
func TestAnEntryWithNoStatedExpiryIsKeptRatherThanDropped(t *testing.T) {
	r := NewRevocations(0, FailOpen)
	if err := r.Install(Snapshot{
		AsOf:        revNow.Unix(),
		Revocations: []Revocation{{JTI: "tok-1"}},
	}, revNow); err != nil {
		t.Fatal(err)
	}
	if !r.Check("tok-1", "s", 0, revNow.Add(24*time.Hour)).Revoked {
		t.Fatal("an entry with no stated expiry was dropped as though it had one in the past")
	}
}

func TestTheHookIsTheShapeOptionsRevokedTakesAndShowsTheCallerTheBasis(t *testing.T) {
	r := holdingOne(t)
	var seen []Basis
	var o Options
	o.Revoked = r.Hook(revNow, func(a Answer) { seen = append(seen, a.Basis) })
	if !o.Revoked("tok-1", "user://acme/alice", revNow.Unix()) {
		t.Fatal("the hook did not refuse a revoked token")
	}
	if o.Revoked("tok-2", "user://acme/alice", revNow.Unix()) {
		t.Fatal("the hook refused a token nobody revoked")
	}
	if len(seen) != 2 || seen[0] != BasisListed || seen[1] != BasisAbsent {
		t.Fatalf("the caller was not shown what each answer rested on: %v", seen)
	}
	// nil is allowed, for a caller that has decided to record nothing.
	if !r.Hook(revNow, nil)("tok-1", "", 0) {
		t.Fatal("a nil observer changed the answer")
	}
}

// Copied from a live GET /v1/revocations, not written from the struct: a
// fixture derived from the reader cannot catch the reader misreading.
const liveRevocationsBody = `{"as_of":1800000000,"revocations":[
  {"jti":"tok-1","expires":1800003600,"actor":"user://acme/ops","reason":"key leaked"},
  {"subject":"agent://acme/triage","issued_before":1800000000,
   "expires":1800003600,"actor":"user://acme/ops","reason":"compromised"}]}`

func TestTheBodyVouchryxServesParsesIntoThis(t *testing.T) {
	s, err := ParseSnapshot([]byte(liveRevocationsBody))
	if err != nil {
		t.Fatal(err)
	}
	if s.AsOf != 1800000000 || len(s.Revocations) != 2 {
		t.Fatalf("%+v", s)
	}
	if s.Revocations[0].JTI != "tok-1" {
		t.Fatalf("first entry: %+v", s.Revocations[0])
	}
	if s.Revocations[1].Subject != "agent://acme/triage" || s.Revocations[1].IssuedBefore != 1800000000 {
		t.Fatalf("second entry: %+v", s.Revocations[1])
	}
}

// The distinction as_of exists for. An empty answer is knowledge.
func TestAnEmptyListIsAListAndNotAFailure(t *testing.T) {
	s, err := ParseSnapshot([]byte(`{"as_of":1800000000,"revocations":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	r := NewRevocations(0, FailOpen)
	if err := r.Install(s, revNow); err != nil {
		t.Fatal(err)
	}
	if got := r.Check("tok-1", "s", 0, revNow); got.Basis != BasisAbsent {
		t.Fatalf("an empty list answers a miss and is not the same as never having fetched: %+v", got)
	}
}

func TestABodyThatIsNotAListAtAllIsAnErrorRatherThanAnEmptyList(t *testing.T) {
	for _, raw := range []string{"", "null", "[]", `"revoked"`, "<html>nope</html>", `{"revocations": 7}`} {
		if _, err := ParseSnapshot([]byte(raw)); err == nil {
			t.Fatalf("%q parsed as a revocation list", raw)
		}
	}
}

// Invariant 15's seam, asserted on the SHAPE. The request path takes no
// context and returns no error, so it cannot become a round trip; the fetch
// takes one, which is the negative control that keeps this from passing by
// finding nothing at all.
func TestTheRequestPathCannotBecomeANetworkCall(t *testing.T) {
	ctxType := reflect.TypeOf((*context.Context)(nil)).Elem()
	errType := reflect.TypeOf((*error)(nil)).Elem()

	takesContext := func(m reflect.Method) bool {
		for i := 0; i < m.Type.NumIn(); i++ {
			if m.Type.In(i) == ctxType {
				return true
			}
		}
		return false
	}
	returnsError := func(m reflect.Method) bool {
		for i := 0; i < m.Type.NumOut(); i++ {
			if m.Type.Out(i) == errType {
				return true
			}
		}
		return false
	}
	find := func(name string) reflect.Method {
		m, ok := reflect.TypeOf(&Revocations{}).MethodByName(name)
		if !ok {
			t.Fatalf("%s is gone, so this check measured nothing", name)
		}
		return m
	}

	for _, name := range []string{"Check", "Hook", "Age", "AsOf", "RejectedBackwards"} {
		m := find(name)
		if takesContext(m) || returnsError(m) {
			t.Fatalf("%s takes a context or returns an error, so the request path can now block", name)
		}
	}
	// And the closure Hook hands to Options.Revoked, which is what a caller
	// actually holds: three strings in, one bool out, nothing else.
	hook := reflect.TypeOf((&Revocations{}).Hook(revNow, nil))
	if hook.NumIn() != 3 || hook.NumOut() != 1 || hook.Out(0).Kind() != reflect.Bool {
		t.Fatalf("the hook is no longer the shape Options.Revoked takes: %v", hook)
	}
	if !takesContext(find("Refresh")) {
		t.Fatal("Refresh reaches the network and no longer takes a context, so this check proves nothing")
	}
}

// A failed poll is not an empty list. The held list is untouched and goes on
// ageing, which is what eventually turns it into the operator's fail mode.
func TestAFetchThatFailsLeavesTheHeldListAgeing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no", http.StatusInternalServerError)
	}))
	defer srv.Close()

	r := holdingOne(t)
	later := revNow.Add(20 * time.Second)
	if err := r.Refresh(context.Background(), srv.Client(), srv.URL, later); err == nil {
		t.Fatal("a 500 was taken as a revocation list")
	}
	if age, _ := r.Age(later); age != 20*time.Second {
		t.Fatalf("a failed poll reset the age to %v", age)
	}
	if !r.Check("tok-1", "user://acme/alice", revNow.Unix(), later).Revoked {
		t.Fatal("a failed poll emptied the list")
	}
}

func TestAnOverlongRevocationListIsRefusedRatherThanTruncated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"as_of":1,"revocations":[`)
		one := `{"jti":"` + strings.Repeat("x", 512) + `","expires":9999999999},`
		for written := 0; written < MaxSnapshotBytes; written += len(one) {
			fmt.Fprint(w, one)
		}
		fmt.Fprint(w, `{"jti":"last","expires":9999999999}]}`)
	}))
	defer srv.Close()

	r := NewRevocations(0, FailOpen)
	err := r.Refresh(context.Background(), srv.Client(), srv.URL, revNow)
	if err == nil || !strings.Contains(err.Error(), "over") {
		t.Fatalf("an overlong list was accepted: %v", err)
	}
	if got := r.Check("tok-1", "s", 0, revNow); got.Basis != BasisNever {
		t.Fatalf("a refused body was installed anyway: %+v", got)
	}
}

// The estate-level claim, end to end and over a real socket: a token whose
// signature, binding and expiry are all perfect stops working because somebody
// revoked it. This is the sentence four documents made and nothing performed.
func TestARevokedDelegationIsRefusedByVerifyAfterAPollPicksItUp(t *testing.T) {
	f := newFixture(t)
	revoked := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body := fmt.Sprintf(`{"as_of":%d,"revocations":[]}`, f.now.Unix())
		if revoked {
			body = fmt.Sprintf(
				`{"as_of":%d,"revocations":[{"jti":"tok-1","expires":%d,`+
					`"actor":"user://acme/ops","reason":"key leaked"}]}`,
				f.now.Unix(), f.now.Add(time.Hour).Unix())
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	revs := NewRevocations(0, FailOpen)
	poll := func() {
		if err := revs.Refresh(context.Background(), srv.Client(), srv.URL, f.now); err != nil {
			t.Fatalf("poll: %v", err)
		}
	}
	check := func(proofJTI string) error {
		o := f.opts(f.proofFrom(t, f.holder, proofJTI))
		o.Revoked = revs.Hook(o.Now, nil)
		_, err := Verify(f.mint(t, nil), o)
		return err
	}

	poll()
	if err := check("p1"); err != nil {
		t.Fatalf("before the revocation the token must work: %v", err)
	}

	revoked = true
	poll()
	if err := check("p2"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("after the revocation Verify must refuse it, got %v", err)
	}
}

// go test -race is a gate here, and a poller writing while request paths read
// is the shape this type is for.
func TestAPollerAndARequestPathDoNotRace(t *testing.T) {
	r := NewRevocations(0, FailOpen)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for n := 0; n < 50; n++ {
				_ = r.Install(Snapshot{
					AsOf:        revNow.Unix(),
					Revocations: []Revocation{revJTI("tok-1", revNow.Add(time.Hour))},
				}, revNow)
				_ = r.Check("tok-1", "s", 0, revNow)
				_, _ = r.Age(revNow)
				_ = r.RejectedBackwards()
			}
		}(i)
	}
	wg.Wait()
}

// A 503 carrying a perfectly good body is the case the status check exists
// for, and nothing pinned it until a planted mutant walked straight past the
// suite: the test above serves a 500 whose body is not JSON, so the PARSER was
// refusing it and the status check could have been deleted in silence. A
// gateway, a mesh or a cache in front of vouchryx is exactly the thing that
// answers a non-200 with a JSON payload, and reading one as "nothing is
// revoked" would install an empty list over a good one.
func TestANonTwoHundredAnswerIsNeverReadAsAnEmptyList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, `{"as_of":%d,"revocations":[]}`, revNow.Add(time.Hour).Unix())
	}))
	defer srv.Close()

	r := holdingOne(t)
	later := revNow.Add(20 * time.Second)
	err := r.Refresh(context.Background(), srv.Client(), srv.URL, later)
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("a 503 with a valid body was taken as a revocation list: %v", err)
	}
	if !r.Check("tok-1", "user://acme/alice", revNow.Unix(), later).Revoked {
		t.Fatal("a 503 emptied the held list")
	}
	if age, _ := r.Age(later); age != 20*time.Second {
		t.Fatalf("a 503 reset the age to %v", age)
	}
}

// TestTheDefaultFailModeRefuses pins the ZERO VALUE, which is the mode every
// deployment that never names one gets. Every other test in this file passes a
// mode explicitly, so before this one the default was the single most-used
// setting in the package and the only one nothing asserted.
func TestTheDefaultFailModeRefuses(t *testing.T) {
	var unset FailMode
	if unset != FailClosed {
		t.Fatalf("the unnamed fail mode is %v, want closed: an operator who never chose gets whatever this is", unset)
	}
	// A cache nobody ever fetched into, built without naming a mode. This is
	// exactly the shape a half-wired door has.
	a := new(Revocations).Check("tok-1", "user://acme/alice", revNow.Unix(), revNow)
	if !a.Revoked || a.Basis != BasisNever {
		t.Fatalf("a list nobody fetched answered %+v, want refused on BasisNever", a)
	}
}
