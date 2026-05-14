package policy

import "testing"

func TestRank(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"allow", 0},
		{"ask", 1},
		{"deny", 2},
		{"unknown", 1},
		{"", 1},
	}
	for _, c := range cases {
		if got := Rank(c.in); got != c.want {
			t.Errorf("Rank(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestWorstVerdict(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, "ask"},
		{[]string{"allow"}, "allow"},
		{[]string{"allow", "ask"}, "ask"},
		{[]string{"ask", "deny", "allow"}, "deny"},
		{[]string{"deny", "deny"}, "deny"},
		{[]string{"unknown"}, "unknown"}, // first wins when ranks equal
	}
	for _, c := range cases {
		if got := WorstVerdict(c.in); got != c.want {
			t.Errorf("WorstVerdict(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
