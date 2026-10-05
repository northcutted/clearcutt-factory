// Package container runs one-off containers through docker or podman, for
// steps that need a distribution's own tools (apt, dnf, nix) at lock time.
package container

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/northcutted/declarative-image-factory/internal/registry"
)

// Runtime returns the docker or podman binary to use. pref is auto, docker, or
// podman; FACTORY_RUNTIME overrides it.
func Runtime(pref string) (string, error) {
	if env := os.Getenv("FACTORY_RUNTIME"); env != "" {
		pref = env
	}
	switch pref {
	case "docker", "podman":
		if p, err := exec.LookPath(pref); err == nil {
			return p, nil
		}
		return "", fmt.Errorf("container runtime %s not found on PATH", pref)
	}
	for _, c := range []string{"docker", "podman"} {
		if p, err := exec.LookPath(c); err == nil {
			return p, nil
		}
	}
	return "", errors.New("no container runtime found: install docker or podman")
}

// RunFunc runs script with sh in image for platform and returns stdout.
type RunFunc func(ctx context.Context, image, platform, script string, args ...string) ([]byte, error)

// Runner runs scripts in containers.
type Runner struct {
	Runtime string // auto, docker, podman
}

// Run executes script with sh in image for platform, passing args as $1….
// It returns stdout; on failure the error carries the tail of stderr.
func (r Runner) Run(ctx context.Context, image, platform, script string, args ...string) ([]byte, error) {
	rt, err := Runtime(r.Runtime)
	if err != nil {
		return nil, err
	}
	cmdArgs := []string{"run", "--rm", "--pull=missing"}
	if platform != "" {
		cmdArgs = append(cmdArgs, "--platform", platform)
	}
	cmdArgs = append(cmdArgs, "--entrypoint", "sh", registry.Qualify(image), "-c", script, "factory")
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.CommandContext(ctx, rt, cmdArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("running %s (%s): %w\n%s", image, platform, err, tail(stderr.String(), 25))
	}
	return stdout.Bytes(), nil
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
