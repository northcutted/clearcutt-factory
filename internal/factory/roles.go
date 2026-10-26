package factory

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/northcutted/clearcutt-factory/internal/manifest"
)

// RolesOptions are roles' settings.
type RolesOptions struct {
	// Dir is where the stacks are looked for (default: the current
	// directory): every kind Stack file below it, except under hidden
	// directories, out, node_modules, and .clearcutt-factory.
	Dir string
}

// Image roles, as the stacks give them: build (a stack's spec.build names
// the image: the toolchain apps build with) and run (spec.run: the image
// apps ship on). images.yml records them in its published output, and
// notify.yml announces a build image as clearcutt.build-image-published, a
// run image (or one no stack names) as clearcutt.run-image-published.
const (
	RoleBuild = "build"
	RoleRun   = "run"
)

// Roles prints what the stacks in the repository make of the image
// manifest: build, run, both, or nothing, one per line, and writes
// roles=… (space-separated) to $GITHUB_OUTPUT. A stack names an image by
// its manifest path (spec.build: ../images/build-go/image.yaml), which is
// what ties it to a manifest here; a stack naming an image by reference
// says nothing about which manifest builds it.
func Roles(ctx context.Context, opts Options, ro RolesOptions) error {
	roles, err := imageRoles(opts.ManifestPath, ro.Dir)
	if err != nil {
		return err
	}
	for _, r := range roles {
		opts.printf("%s", r)
	}
	if path := os.Getenv("GITHUB_OUTPUT"); path != "" {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(f, "roles=%s\n", strings.Join(roles, " ")); err != nil {
			_ = f.Close()
			return err
		}
		return f.Close()
	}
	return nil
}

// imageRoles returns the roles the stacks under dir give the manifest at
// manifestPath, sorted. The manifest must be an image; a stack that
// doesn't load is an error (it would be one for stack push too).
func imageRoles(manifestPath, dir string) ([]string, error) {
	m, err := manifest.Load(manifestPath)
	if err != nil {
		return nil, err
	}
	if m.Kind != manifest.KindImage {
		return nil, fmt.Errorf("%s is a %s; stacks name images (kind %s)", manifestPath, m.Kind, manifest.KindImage)
	}
	stacks, err := findStacks(dir)
	if err != nil {
		return nil, err
	}
	var roles []string
	for _, p := range stacks {
		st, err := manifest.LoadStack(p)
		if err != nil {
			return nil, err
		}
		for role, v := range map[string]string{RoleBuild: st.Spec.Build, RoleRun: st.Spec.Run} {
			if !manifest.IsStackFile(v) {
				continue
			}
			named, err := filepath.Abs(filepath.Join(filepath.Dir(p), v))
			if err != nil {
				return nil, err
			}
			if sameFile(named, m.Path) && !slices.Contains(roles, role) {
				roles = append(roles, role)
			}
		}
	}
	sort.Strings(roles)
	return roles, nil
}

// skippedDirs are never searched for stacks.
var skippedDirs = map[string]bool{"out": true, "node_modules": true, ".clearcutt-factory": true}

// findStacks lists the kind Stack YAML files under dir.
func findStacks(dir string) ([]string, error) {
	if dir == "" {
		dir = "."
	}
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != dir && (strings.HasPrefix(d.Name(), ".") || skippedDirs[d.Name()]) {
				return filepath.SkipDir
			}
			return nil
		}
		if !manifest.IsStackFile(d.Name()) {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var head struct {
			Kind string `yaml:"kind"`
		}
		if yaml.Unmarshal(b, &head) == nil && head.Kind == manifest.KindStack {
			out = append(out, p)
		}
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: no such directory", dir)
	}
	sort.Strings(out)
	return out, err
}

// sameFile reports whether two paths name the same file, through symlinks.
func sameFile(a, b string) bool {
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	return err == nil && os.SameFile(ai, bi)
}
