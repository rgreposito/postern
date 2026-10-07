package policy

import "testing"

func TestMatch(t *testing.T) {
	cases := []struct {
		p, s string
		want bool
	}{
		{"abc", "abc", true},
		{"abc", "ab", false},
		{"abc", "abcd", false},
		{"", "", true},
		{"", "x", false},

		{"tcp://db.prod:5432", "tcp://db.prod:5432", true},
		{"tcp://*.prod:5432", "tcp://db.prod:5432", true},
		{"tcp://*.prod:5432", "tcp://db.dev:5432", false},
		{"tcp://*.prod:5432", "tcp://a/b.prod:5432", false}, // * does not cross /

		{"spiffe://prod/**", "spiffe://prod/ns/pay/sa/ledger", true},
		{"spiffe://prod/**", "spiffe://prod/", true},
		{"spiffe://prod/**", "spiffe://prod", true},
		{"spiffe://prod/**", "spiffe://staging/ns/pay", false},

		{"mcp://splunk.*", "mcp://splunk.query", true},
		{"mcp://splunk.*", "mcp://splunk.query.extra", true},
		{"mcp://splunk.*", "mcp://elastic.search", false},

		{"user@*", "user@corp", true},
		{"*@corp.example", "rafa@corp.example", true},

		{"fo?", "foo", true},
		{"fo?", "fo", false},
		{"fo?", "fooo", false},
		{"fo?", "fo/", false},

		{"foo*", "foo", false}, // * is one-or-more
		{"foo*", "food", true},
		{"foo*", "foo/bar", false},

		{"**", "anything/at/all", true},
		{"**", "", true},
		{"a/**/b", "a/b", true},
		{"a/**/b", "a/x/y/b", true},
		{"a/**/b", "a/x/y/c", false},
	}
	for _, tc := range cases {
		got := Match(tc.p, tc.s)
		if got != tc.want {
			t.Errorf("Match(%q, %q) = %v, want %v", tc.p, tc.s, got, tc.want)
		}
	}
}

func FuzzMatchDoesNotPanic(f *testing.F) {
	f.Add("tcp://*.prod:5432", "tcp://db.prod:5432")
	f.Add("**", "")
	f.Add("a*b?c**", "axxbyczz")
	f.Fuzz(func(t *testing.T, p, s string) {
		_ = Match(p, s)
		if Match(p, s) && p != "" && !hasMeta(p) && p != s {
			t.Fatalf("literal pattern %q matched %q", p, s)
		}
	})
}

func hasMeta(p string) bool {
	for i := 0; i < len(p); i++ {
		if p[i] == '*' || p[i] == '?' {
			return true
		}
	}
	return false
}
