// Package smoke runs a manifest's smoke test in a built image, through
// docker or podman, before the image is pushed.
package smoke

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/northcutted/declarative-image-factory/internal/container"
	"github.com/northcutted/declarative-image-factory/internal/manifest"
)

// Exec runs a container runtime command and returns its stdout and stderr.
// Tests replace it.
type Exec func(ctx context.Context, args ...string) (stdout, stderr []byte, err error)

// Runner runs smoke tests.
type Runner struct {
	// Runtime is auto, docker, or podman.
	Runtime string
	// WorkDir holds the image tarballs handed to the runtime.
	WorkDir string
	Exec    Exec
	// Poll is how often an HTTP test retries (default 500ms).
	Poll time.Duration
}

// exec returns the command's stdout; a failure carries the tail of both
// streams.
func (r *Runner) exec(ctx context.Context, args ...string) ([]byte, error) {
	stdout, stderr, err := r.run(ctx, args...)
	if err != nil {
		out := strings.TrimSpace(string(stderr) + "\n" + string(stdout))
		return stdout, fmt.Errorf("%s: %w\n%s", args[0], err, tail(out, 20))
	}
	return stdout, nil
}

func (r *Runner) run(ctx context.Context, args ...string) ([]byte, []byte, error) {
	if r.Exec != nil {
		return r.Exec(ctx, args...)
	}
	rt, err := container.Runtime(r.Runtime)
	if err != nil {
		return nil, nil, err
	}
	cmd := exec.CommandContext(ctx, rt, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

// Run loads one platform image into the runtime and runs the test in it.
func (r *Runner) Run(ctx context.Context, img v1.Image, platform, label string, t *manifest.Test) error {
	ref := fmt.Sprintf("localhost/factory-smoke/%s:%s", sanitize(label), sanitize(platform))
	tag, err := name.NewTag(ref)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(r.WorkDir, 0o755); err != nil {
		return err
	}
	tarPath := filepath.Join(r.WorkDir, sanitize(label)+"-"+sanitize(platform)+".tar")
	if err := tarball.WriteToFile(tarPath, tag, img); err != nil {
		return err
	}
	defer func() { _ = os.Remove(tarPath) }()
	if _, err := r.exec(ctx, "load", "-q", "-i", tarPath); err != nil {
		return err
	}
	defer func() { _, _ = r.exec(context.WithoutCancel(ctx), "rmi", "-f", ref) }()

	ctx, cancel := context.WithTimeout(ctx, t.TimeoutOrDefault())
	defer cancel()
	// A named container can be removed even if the client is killed on timeout.
	cname := fmt.Sprintf("factory-smoke-%s-%s-%d", sanitize(label), sanitize(platform), time.Now().UnixNano())
	defer func() { _, _ = r.exec(context.WithoutCancel(ctx), "rm", "-f", cname) }()
	run := []string{"run", "--name", cname, "--platform", platform}
	var args []string
	if len(t.Command) > 0 {
		run = append(run, "--entrypoint", t.Command[0])
		args = t.Command[1:]
	}
	if t.HTTP == nil {
		_, err := r.exec(ctx, append(append(run, ref), args...)...)
		if ctx.Err() != nil {
			return fmt.Errorf("%s did not finish within %s", strings.Join(t.Command, " "), t.TimeoutOrDefault())
		}
		return err
	}
	if _, err := r.exec(ctx, append(append(append(run, "-d", "-p", fmt.Sprintf("127.0.0.1::%d", t.HTTP.Port)), ref), args...)...); err != nil {
		return err
	}
	return r.probe(ctx, cname, t)
}

var hostPortRE = regexp.MustCompile(`:(\d+)\s*$`)

// probe requests the path from the running container until it answers with
// a non-error status, the container exits, or time runs out.
func (r *Runner) probe(ctx context.Context, id string, t *manifest.Test) error {
	logs := func() string {
		stdout, stderr, _ := r.run(context.WithoutCancel(ctx), "logs", id)
		return tail(strings.TrimSpace(string(stdout)+"\n"+string(stderr)), 20)
	}
	out, err := r.exec(ctx, "port", id, fmt.Sprintf("%d/tcp", t.HTTP.Port))
	if err != nil {
		return err
	}
	m := hostPortRE.FindStringSubmatch(strings.TrimSpace(strings.Split(strings.TrimSpace(string(out)), "\n")[0]))
	if m == nil {
		return fmt.Errorf("can't read the published port from %q", out)
	}
	hostPort, _ := strconv.Atoi(m[1])
	path := t.HTTP.Path
	if path == "" {
		path = "/"
	}
	url := fmt.Sprintf("http://127.0.0.1:%d%s", hostPort, path)
	poll := r.Poll
	if poll == 0 {
		poll = 500 * time.Millisecond
	}
	client := &http.Client{Timeout: 5 * time.Second}
	var last string
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode < 400 {
				return nil
			}
			last = resp.Status
		} else {
			last = err.Error()
		}
		if state, err := r.exec(ctx, "inspect", "-f", "{{.State.Running}}", id); err == nil && strings.TrimSpace(string(state)) == "false" {
			return fmt.Errorf("the container exited before answering %s\n%s", path, logs())
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("no successful answer from %s within %s (last: %s)\n%s", path, t.TimeoutOrDefault(), last, logs())
		case <-time.After(poll):
		}
	}
}

// Describe summarizes a test for messages.
func Describe(t *manifest.Test) string {
	var parts []string
	if len(t.Command) > 0 {
		parts = append(parts, strings.Join(t.Command, " "))
	}
	if t.HTTP != nil {
		path := t.HTTP.Path
		if path == "" {
			path = "/"
		}
		parts = append(parts, fmt.Sprintf("GET :%d%s", t.HTTP.Port, path))
	}
	return strings.Join(parts, ", ")
}

var unsafeRE = regexp.MustCompile(`[^a-z0-9._-]+`)

func sanitize(s string) string {
	return strings.Trim(unsafeRE.ReplaceAllString(strings.ToLower(s), "-"), "-.")
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
