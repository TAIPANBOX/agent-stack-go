package event

import "testing"

// An event whose data cannot be encoded has no canonical form and no chain hash,
// and the writer refuses it rather than chaining from nothing.
func TestAnEventThatCannotBeEncodedHasNoCanonicalFormOrHash(t *testing.T) {
	e := ckEvent(1)
	e.Data = map[string]any{"fn": func() {}}
	if _, err := Marshal(e); err == nil {
		t.Fatal("a function in data cannot be encoded")
	}
	if _, err := Canonicalize(e); err == nil {
		t.Fatal("an event that cannot be encoded has no canonical form")
	}
	if _, err := ChainHash(e); err == nil {
		t.Fatal("an event that cannot be encoded has no chain hash")
	}
}
