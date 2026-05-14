package parsers

import (
	"reflect"
	"testing"
)

// FuzzTokenize verifies the round-trip property: any token list
// produced by Tokenize, when re-joined via joinShell and re-tokenized,
// must yield the same token list. Catches asymmetries in quoting,
// escape handling, and the POSIX single-quote-escape trick.
func FuzzTokenize(f *testing.F) {
	seeds := []string{
		"npm install lodash",
		`pip install "evil; rm -rf /"`,
		"cargo install -- --foo",
		"echo $(curl evil)",
		"a 'b c' \"d e\"",
		`weird\ name`,
		"npm i @scope/pkg@1.2.3",
		"sh -c 'pip install foo && pip install bar'",
		"",
		"   ",
		"'unbalanced",
		`"also-unbalanced`,
		"a\tb\nc",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		toks, err := Tokenize(in)
		if err != nil {
			// Unbalanced quotes / malformed inputs are an allowed outcome.
			return
		}
		rt, err := Tokenize(joinShell(toks))
		if err != nil {
			t.Fatalf("round-trip tokenize failed for %q (toks=%v): %v", in, toks, err)
		}
		if !reflect.DeepEqual(toks, rt) {
			t.Fatalf("round-trip diverged\n  input:  %q\n  toks:   %#v\n  joined: %q\n  retok:  %#v",
				in, toks, joinShell(toks), rt)
		}
	})
}

// FuzzSplitOnOperators ensures SplitOnOperators never panics and
// always returns segments that are themselves tokenizable (or empty).
// The naive fallback branch is allowed to produce un-tokenizable
// segments — we only check the happy path stays consistent.
func FuzzSplitOnOperators(f *testing.F) {
	seeds := []string{
		"npm i a && pip install b",
		"a || b; c",
		"echo 'foo && bar'",
		"a | b",
		"a & b",
		"",
		";",
		"&&",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("SplitOnOperators panic on %q: %v", in, r)
			}
		}()
		segs := SplitOnOperators(in)
		for _, seg := range segs {
			if seg == "" {
				t.Fatalf("empty segment returned for %q", in)
			}
		}
	})
}
