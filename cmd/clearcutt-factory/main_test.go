package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"strings"
	"testing"
)

// TestEveryFlagHasHelp: -h describes every flag of every command.
func TestEveryFlagHasHelp(t *testing.T) {
	for _, c := range commands {
		fs, _, exec := flagsFor(c.name, &bytes.Buffer{}, &bytes.Buffer{})
		if fs == nil || exec == nil {
			t.Fatalf("%s: no flag set", c.name)
		}
		n := 0
		fs.VisitAll(func(f *flag.Flag) {
			n++
			if strings.TrimSpace(f.Usage) == "" {
				t.Errorf("%s: flag -%s has no help string", c.name, f.Name)
			}
		})
		if n < 4 {
			t.Errorf("%s: %d flags, expected the common ones at least", c.name, n)
		}
	}
}

// TestUsageErrors: a flag that doesn't exist, an unknown command, a bad
// subcommand, or stray arguments print what was wrong and the usage, once
// each, and exit 2.
func TestUsageErrors(t *testing.T) {
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"build", "--bogus"}, "flag provided but not defined: -bogus"},
		{[]string{"lock", "-update-package"}, "flag needs an argument: -update-package"},
		{[]string{"frobnicate"}, `unknown command "frobnicate"`},
		{[]string{"stack", "pull"}, "stack takes the subcommand push"},
		{[]string{"render", "extra"}, "unexpected arguments: extra"},
		{nil, ""},
	} {
		var out, errOut bytes.Buffer
		err := run(context.Background(), c.args, &out, &errOut)
		var ue usageError
		if !errors.As(err, &ue) {
			t.Errorf("%q: got %v, want a usage error", c.args, err)
			continue
		}
		if code := exit(err, &errOut); code != 2 {
			t.Errorf("%q: exit %d, want 2", c.args, code)
		}
		s := errOut.String()
		if n := strings.Count(s, "Usage:"); n != 1 {
			t.Errorf("%q: the usage was printed %d times:\n%s", c.args, n, s)
		}
		if c.want != "" && strings.Count(s, c.want) != 1 {
			t.Errorf("%q: stderr should name the problem once (%q):\n%s", c.args, c.want, s)
		}
		if out.Len() != 0 {
			t.Errorf("%q: wrote to stdout: %s", c.args, out.String())
		}
	}
}

// TestHelp: -h prints the usage and the command's flags, and exits 0.
func TestHelp(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run(context.Background(), []string{"build", "-h"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{"Usage:", "Flags of build:", "-push", "-force-tags", "move the tags even"} {
		if !strings.Contains(s, want) {
			t.Errorf("build -h lacks %q:\n%s", want, s)
		}
	}
	if strings.Count(s, "Usage:") != 1 || errOut.Len() != 0 {
		t.Errorf("build -h: usage %d times, stderr %q", strings.Count(s, "Usage:"), errOut.String())
	}
	out.Reset()
	if err := run(context.Background(), []string{"help"}, &out, &errOut); err != nil || !strings.Contains(out.String(), "Usage:") {
		t.Errorf("help: %v\n%s", err, out.String())
	}
	out.Reset()
	if err := run(context.Background(), []string{"version"}, &out, &errOut); err != nil || strings.TrimSpace(out.String()) == "" {
		t.Errorf("version: %v %q", err, out.String())
	}
}

// TestOtherErrorsExit1: an error from the command itself is reported
// without the usage.
func TestOtherErrorsExit1(t *testing.T) {
	var errOut bytes.Buffer
	if code := exit(errors.New("cosign not found"), &errOut); code != 1 || errOut.String() != "error: cosign not found\n" {
		t.Errorf("exit %d, stderr %q", code, errOut.String())
	}
	if code := exit(nil, &errOut); code != 0 {
		t.Errorf("nil: exit %d", code)
	}
}
