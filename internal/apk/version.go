package apk

import (
	"strconv"
	"strings"
)

// CompareVersions orders apk versions (e.g. 1.2.3a_rc1-r4) the way apk-tools
// does for the cases that occur in practice: numeric components, an optional
// trailing letter, _suffixes, then the -rN package revision.
func CompareVersions(a, b string) int {
	va, vb := parseVersion(a), parseVersion(b)
	for i := 0; i < max(len(va.nums), len(vb.nums)); i++ {
		if i >= len(va.nums) {
			return -1
		}
		if i >= len(vb.nums) {
			return 1
		}
		if c := cmpInt(va.nums[i], vb.nums[i]); c != 0 {
			return c
		}
	}
	if c := strings.Compare(va.letter, vb.letter); c != 0 {
		return c
	}
	for i := 0; i < max(len(va.suffixes), len(vb.suffixes)); i++ {
		sa, sb := suffix{rank: 0}, suffix{rank: 0}
		if i < len(va.suffixes) {
			sa = va.suffixes[i]
		}
		if i < len(vb.suffixes) {
			sb = vb.suffixes[i]
		}
		if c := cmpInt(sa.rank, sb.rank); c != 0 {
			return c
		}
		if c := cmpInt(sa.num, sb.num); c != 0 {
			return c
		}
	}
	return cmpInt(va.rev, vb.rev)
}

type version struct {
	nums     []int
	letter   string
	suffixes []suffix
	rev      int
}

// suffix ranks: pre-release suffixes sort before "no suffix" (0), post-release after.
type suffix struct{ rank, num int }

var suffixRank = map[string]int{
	"alpha": -4, "beta": -3, "pre": -2, "rc": -1,
	"cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5,
}

func parseVersion(s string) version {
	var v version
	if i := strings.LastIndex(s, "-r"); i >= 0 {
		if n, err := strconv.Atoi(s[i+2:]); err == nil {
			v.rev = n
			s = s[:i]
		}
	}
	if i := strings.Index(s, "~"); i >= 0 { // commit hash, not ordered
		s = s[:i]
	}
	parts := strings.Split(s, "_")
	core := parts[0]
	for _, p := range parts[1:] {
		name := strings.TrimRightFunc(p, isDigit)
		num, _ := strconv.Atoi(p[len(name):])
		rank, ok := suffixRank[name]
		if !ok {
			rank = 6 // unknown suffixes sort last
		}
		v.suffixes = append(v.suffixes, suffix{rank, num})
	}
	if n := len(core); n > 0 && !isDigit(rune(core[n-1])) {
		v.letter = core[n-1:]
		core = core[:n-1]
	}
	for _, f := range strings.Split(core, ".") {
		n, _ := strconv.Atoi(f)
		v.nums = append(v.nums, n)
	}
	return v
}

func isDigit(r rune) bool { return r >= '0' && r <= '9' }

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// Satisfies reports whether version v meets constraint op/want (apk dependency
// operators: =, >=, <=, >, <, ~ (fuzzy prefix), ><, or empty for any).
func Satisfies(v, op, want string) bool {
	if op == "" {
		return true
	}
	if op == "~" || op == "=~" {
		return v == want || strings.HasPrefix(v, want+".") || strings.HasPrefix(v, want+"-") || strings.HasPrefix(v, want+"_")
	}
	c := CompareVersions(v, want)
	switch op {
	case "=", "==":
		return c == 0
	case ">=":
		return c >= 0
	case "<=":
		return c <= 0
	case ">":
		return c > 0
	case "<":
		return c < 0
	case "><":
		return c != 0
	}
	return false
}
