package manifest

import (
	"errors"
	"fmt"
	"maps"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The checks below decide what may be printed into a Containerfile. The
// renderer prints some values as they are (USER, WORKDIR, ENV names, COPY
// paths, image references, cache mount targets), so a newline or a space
// there would end the instruction or start another one; quoted values
// (ENV and LABEL values, shell arguments) still can't hold a newline, which
// would end the line. manifest validation and the renderer both apply them,
// so a manifest or lock that fails one is refused before anything is built.

var (
	userRE    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*(:[A-Za-z0-9_][A-Za-z0-9_.-]*)?$`)
	envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)
	// pathRE is an absolute path the Containerfile may hold unquoted: no
	// whitespace, and none of what BuildKit reads in COPY, WORKDIR, and
	// mount options ($ variables, \ escapes, quotes, globs, the , and = of
	// --mount).
	pathRE = regexp.MustCompile(`^/[A-Za-z0-9._+@%:/~-]*$`)
	// refRE is an image reference or a URL as the Containerfile holds it.
	refRE = regexp.MustCompile(`^[A-Za-z0-9._/:@+%?&=~#,;!()-]+$`)
	// digestRE is the OCI digest grammar.
	digestRE   = regexp.MustCompile(`^[a-z0-9]+(?:[+._-][a-z0-9]+)*:[a-zA-Z0-9=_-]+$`)
	platformRE = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9_]+$`)
)

// CheckUser checks spec.user: a user name or ID, optionally with a group
// (65532, nonroot, 65532:65532).
func CheckUser(u string) error {
	if !userRE.MatchString(u) {
		return fmt.Errorf("%q must be a user name or ID, optionally :group (letters, digits, _ . -)", u)
	}
	return nil
}

// UserIsRoot reports whether spec.user names root: the user root, or ID 0
// however it is written (0, 00). An empty user is the base image's, which
// is root unless the base says otherwise, so it counts as root too.
func UserIsRoot(u string) bool {
	name, _, _ := strings.Cut(u, ":")
	if name == "" || name == "root" {
		return true
	}
	id, err := strconv.ParseUint(name, 10, 64)
	return err == nil && id == 0
}

// CheckEnvName checks an environment variable's name (spec.env,
// spec.buildEnv).
func CheckEnvName(k string) error {
	if !envNameRE.MatchString(k) {
		return fmt.Errorf("%q must start with a letter or _ and hold only letters, digits, _ . -", k)
	}
	return nil
}

// CheckPath checks an absolute path the Containerfile holds unquoted.
func CheckPath(p string) error {
	if !pathRE.MatchString(p) {
		return fmt.Errorf("%q must be an absolute path of letters, digits, and . _ + @ %% : / ~ - (no spaces, quotes, $, \\, globs, commas, or =)", p)
	}
	return nil
}

// CheckRef checks an image reference or URL the Containerfile holds
// unquoted.
func CheckRef(r string) error {
	if !refRE.MatchString(r) {
		return fmt.Errorf("%q is not a reference or URL the Containerfile can hold (no spaces, quotes, $, \\, or control characters)", r)
	}
	return nil
}

// CheckDigest checks a content digest (sha256:…).
func CheckDigest(d string) error {
	if !digestRE.MatchString(d) {
		return fmt.Errorf("%q is not a digest like sha256:…", d)
	}
	return nil
}

// CheckPlatform checks a platform (linux/amd64).
func CheckPlatform(p string) error {
	if !platformRE.MatchString(p) {
		return fmt.Errorf("platform %q must look like linux/amd64", p)
	}
	return nil
}

// CheckLine checks text the Containerfile holds quoted or in a comment: one
// line of valid UTF-8, with no control characters but tabs.
func CheckLine(s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("%q is not valid UTF-8", s)
	}
	for _, r := range s {
		if r != '\t' && unicode.IsControl(r) || r == ' ' || r == ' ' {
			return fmt.Errorf("%q holds a newline or another control character", s)
		}
	}
	return nil
}

// CheckWord checks a value the Containerfile holds unquoted or as one shell
// word: CheckLine, non-empty, and no whitespace.
func CheckWord(s string) error {
	if err := CheckLine(s); err != nil {
		return err
	}
	if s == "" || strings.IndexFunc(s, unicode.IsSpace) >= 0 {
		return fmt.Errorf("%q must be non-empty with no whitespace", s)
	}
	return nil
}

// CheckScript checks a shell script the Containerfile holds in a heredoc:
// valid UTF-8, lines ending in \n, and no control characters but tabs and
// newlines.
func CheckScript(s string) error {
	if !utf8.ValidString(s) {
		return errors.New("is not valid UTF-8")
	}
	for _, r := range s {
		if r != '\t' && r != '\n' && unicode.IsControl(r) {
			return fmt.Errorf("holds the control character %U (lines must end in \\n alone)", r)
		}
	}
	return nil
}

// CheckArgs checks exec-form arguments (entrypoint, cmd, test.command),
// which the Containerfile holds as JSON: any text, as valid UTF-8.
func CheckArgs(args []string) error {
	for _, a := range args {
		if !utf8.ValidString(a) {
			return fmt.Errorf("%q is not valid UTF-8", a)
		}
	}
	return nil
}

// CheckName checks a manifest, tool, or stack name.
func CheckName(n string) error {
	if !nameRE.MatchString(n) {
		return fmt.Errorf("%q must match %s", n, nameRE)
	}
	return nil
}

// CheckMode checks a file mode (0755, 644).
func CheckMode(m string) error {
	if !modeRE.MatchString(m) {
		return fmt.Errorf("mode %q must be octal like 0755", m)
	}
	return nil
}

// CheckSafe applies the checks above to every value of the spec (and an
// app's stack) that the Containerfile holds, and returns what fails.
func (m *Manifest) CheckSafe() []error {
	var errs []error
	check := func(field string, err error) {
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", field, err))
		}
	}
	s := m.Spec
	for i, t := range s.Tools {
		where := fmt.Sprintf("spec.tools[%d] (%s)", i, t.Name)
		check(where+".name", CheckName(t.Name))
		if t.Dest != "" {
			check(where+".dest", CheckPath(t.Dest))
		}
		if t.Mode != "" {
			check(where+".mode", CheckMode(t.Mode))
		}
		switch t.From {
		case FromOCI:
			check(where+".path", CheckPath(t.Path))
		case FromGo:
			check(where+".package", CheckWord(t.Package))
		case FromBuild:
			check(where+".run", CheckScript(t.Run))
		}
	}
	for i, f := range s.Files {
		where := fmt.Sprintf("spec.files[%d]", i)
		check(where+".src", CheckLine(filepath.Base(f.AbsSrc)))
		if !path.IsAbs(f.Dst) {
			check(where+".dst", fmt.Errorf("%q must be absolute", f.Dst))
		}
		check(where+".dst", CheckLine(f.Dst))
		if f.Mode != "" {
			check(where+".mode", CheckMode(f.Mode))
		}
	}
	for _, env := range []struct {
		field string
		vars  map[string]string
	}{{"spec.env", s.Env}, {"spec.buildEnv", s.BuildEnv}} {
		for _, k := range slices.Sorted(maps.Keys(env.vars)) {
			check(env.field+" name", CheckEnvName(k))
			check(env.field+"."+k, CheckLine(env.vars[k]))
		}
	}
	for _, k := range slices.Sorted(maps.Keys(s.Labels)) {
		check("spec.labels key", CheckLine(k))
		check("spec.labels."+k, CheckLine(s.Labels[k]))
	}
	if s.User != "" {
		check("spec.user", CheckUser(s.User))
	}
	if s.Workdir != "" {
		check("spec.workdir", CheckPath(s.Workdir))
	}
	check("spec.entrypoint", CheckArgs(s.Entrypoint))
	check("spec.cmd", CheckArgs(s.Cmd))
	if st := m.Stack; st != nil {
		check("stack metadata.name", CheckName(st.Metadata.Name))
		check("stack spec.appDir", CheckPath(st.Spec.AppDir))
		for _, c := range st.Spec.Caches {
			check("stack spec.caches", CheckPath(c))
		}
		for i := range st.Spec.Steps {
			check(fmt.Sprintf("stack spec.steps[%d]", i), CheckScript(m.StepScript(i)))
		}
	}
	return errs
}
