package ghaction

import (
	"bytes"
	"strings"
	"testing"
)

func TestEscapeMessage(t *testing.T) {
	cases := []struct{ in, want string }{
		{"hello", "hello"},
		{"a%b", "a%25b"},
		{"line\nline", "line%0Aline"},
		{"a\r\nb", "a%0D%0Ab"},
	}
	for _, c := range cases {
		if got := escapeMessage(c.in); got != c.want {
			t.Errorf("escapeMessage(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEscapeProperty(t *testing.T) {
	if got := escapeProperty("path/to:thing,more"); got != "path/to%3Athing%2Cmore" {
		t.Errorf("escapeProperty: %q", got)
	}
}

func TestEmit_NoticeWithFile(t *testing.T) {
	var buf bytes.Buffer
	Notice("hi there", Annotation{File: "src/app.go", Title: "Watch", Out: &buf})
	got := buf.String()
	if !strings.HasPrefix(got, "::notice ") {
		t.Errorf("missing prefix: %q", got)
	}
	if !strings.Contains(got, "file=src/app.go") {
		t.Errorf("missing file prop: %q", got)
	}
	if !strings.Contains(got, "title=Watch") {
		t.Errorf("missing title prop: %q", got)
	}
	if !strings.HasSuffix(got, "::hi there\n") {
		t.Errorf("missing message: %q", got)
	}
}

func TestEmit_ErrorEscapesMessage(t *testing.T) {
	var buf bytes.Buffer
	Error("a\nb%c", Annotation{Out: &buf})
	got := buf.String()
	if !strings.Contains(got, "a%0Ab%25c") {
		t.Errorf("message not escaped: %q", got)
	}
}

func TestEmit_NoPropsOmitsHeader(t *testing.T) {
	var buf bytes.Buffer
	Notice("plain", Annotation{Out: &buf})
	got := buf.String()
	if got != "::notice::plain\n" {
		t.Errorf("got %q", got)
	}
}
