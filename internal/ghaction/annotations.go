// Package ghaction emits GitHub Actions workflow commands.
package ghaction

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// escapeMessage escapes characters the workflow-command parser eats.
func escapeMessage(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}

// escapeProperty escapes property values (additionally `,` and `:`).
func escapeProperty(s string) string {
	s = escapeMessage(s)
	s = strings.ReplaceAll(s, ",", "%2C")
	s = strings.ReplaceAll(s, ":", "%3A")
	return s
}

// Annotation captures the optional fields of a workflow command.
type Annotation struct {
	File  string
	Line  int
	Col   int
	Title string
	Out   io.Writer
}

func emit(level, message string, a Annotation) {
	out := a.Out
	if out == nil {
		out = os.Stdout
	}
	var props []string
	if a.File != "" {
		props = append(props, "file="+escapeProperty(a.File))
	}
	if a.Line > 0 {
		props = append(props, fmt.Sprintf("line=%d", a.Line))
	}
	if a.Col > 0 {
		props = append(props, fmt.Sprintf("col=%d", a.Col))
	}
	if a.Title != "" {
		props = append(props, "title="+escapeProperty(a.Title))
	}
	head := "::" + level
	if len(props) > 0 {
		head += " " + strings.Join(props, ",")
	}
	fmt.Fprintf(out, "%s::%s\n", head, escapeMessage(message))
}

func Error(message string, a Annotation)   { emit("error", message, a) }
func Warning(message string, a Annotation) { emit("warning", message, a) }
func Notice(message string, a Annotation)  { emit("notice", message, a) }
