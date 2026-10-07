package policy

import "unicode/utf8"

// Match reports whether val matches pattern.
//
// Syntax is small on purpose:
//
//	*   one or more runes, not including '/'
//	**  any runes, including '/' and the empty string
//	?   exactly one rune, not '/'
//
// No character classes, no escaping. If you need a literal '*' in an
// identifier you picked a bad identifier.
//
// A slash immediately before `**` is optional so `spiffe://prod/**`
// matches both `spiffe://prod` and `spiffe://prod/ns/x`.
func Match(pattern, val string) bool {
	return glob(pattern, val)
}

func glob(p, s string) bool {
	for len(p) > 0 {
		switch p[0] {
		case '*':
			double := len(p) > 1 && p[1] == '*'
			if double {
				p = p[2:]
				if p == "" {
					return true
				}
				cands := []string{p}
				if p[0] == '/' {
					cands = append(cands, p[1:])
				}
				for _, cp := range cands {
					if glob(cp, s) {
						return true
					}
					for i := 0; i < len(s); i++ {
						if glob(cp, s[i+1:]) {
							return true
						}
					}
				}
				return false
			}
			p = p[1:]
			// '*' is one-or-more, not zero-or-more. `foo*` matches
			// 'food' but not 'foo'. that surprised me once; keeping
			// it explicit so the tests document it.
			if s == "" || s[0] == '/' {
				return false
			}
			for i := 0; i < len(s); {
				if s[i] == '/' {
					return false
				}
				_, n := utf8.DecodeRuneInString(s[i:])
				i += n
				if glob(p, s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if s == "" || s[0] == '/' {
				return false
			}
			_, n := utf8.DecodeRuneInString(s)
			p, s = p[1:], s[n:]
		default:
			// `/` in front of `**` is optional. otherwise
			// `foo/**` would refuse `foo`.
			if p[0] == '/' && len(p) >= 3 && p[1] == '*' && p[2] == '*' {
				if glob(p[1:], s) {
					return true
				}
			}
			if s == "" || p[0] != s[0] {
				return false
			}
			p, s = p[1:], s[1:]
		}
	}
	return s == ""
}
