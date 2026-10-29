// Package builder runs BuildKit with the settings that make output
// reproducible: a pinned BuildKit, SOURCE_DATE_EPOCH, rewrite-timestamp, and an
// OCI layout output whose index digest is the image digest.
package builder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/northcutted/clearcutt-factory/internal/container"
	"github.com/northcutted/clearcutt-factory/internal/registry"
)

// Request describes one build.
type Request struct {
	ContextDir      string // staged context containing the Containerfile
	Containerfile   string // name relative to ContextDir
	Platforms       []string
	SourceDateEpoch int64
	OutDir          string // receives the OCI layout (OutDir/image) and metadata
	NoCache         bool
	BuildKitImage   string // pinned moby/buildkit image
	Registries      []string
	// Annotations are extra OCI exporter options (annotation-manifest[…].k=v).
	Annotations []string
}

// Result points at the built OCI layout.
type Result struct {
	LayoutDir string
	Digest    string
}

// Config selects how BuildKit runs.
type Config struct {
	Runtime string // auto, docker, podman
	Addr    string // remote buildkitd; uses local buildctl
	Stdout  io.Writer
	Stderr  io.Writer
	// CacheVolume persists BuildKit state between runs. Ignored with NoCache.
	CacheVolume string
	// WriteAuth writes registry credentials for a containerized BuildKit.
	WriteAuth func(path string, registries []string) error
	// BuildkitdConfig is a buildkitd.toml for a containerized BuildKit.
	BuildkitdConfig string
	// Network is the BuildKit container's network (e.g. host).
	Network string
}

// buildkitdConfig is where the container's buildkitd reads BuildkitdConfig.
const buildkitdConfig = "/etc/buildkit/buildkitd.toml"

// Build runs the build and returns the layout and its index digest.
func Build(ctx context.Context, cfg Config, req Request) (*Result, error) {
	layoutDir := filepath.Join(req.OutDir, "image")
	if err := os.RemoveAll(layoutDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(req.OutDir, 0o755); err != nil {
		return nil, err
	}
	meta := filepath.Join(req.OutDir, "metadata.json")
	_ = os.Remove(meta)

	args := func(ctxDir, outDir string) []string {
		a := []string{
			"build",
			"--frontend", "dockerfile.v0",
			"--local", "context=" + ctxDir,
			"--local", "dockerfile=" + ctxDir,
			"--opt", "filename=" + req.Containerfile,
			"--opt", "platform=" + strings.Join(req.Platforms, ","),
			"--opt", fmt.Sprintf("build-arg:SOURCE_DATE_EPOCH=%d", req.SourceDateEpoch),
			"--output", strings.Join(append([]string{"type=oci,dest=" + outDir + "/image,tar=false,rewrite-timestamp=true"}, req.Annotations...), ","),
			"--metadata-file", outDir + "/metadata.json",
			"--progress", "plain",
		}
		if req.NoCache {
			a = append(a, "--no-cache")
		}
		return a
	}

	var cmd *exec.Cmd
	var rt string // the container runtime, when BuildKit runs in a container
	if cfg.Addr != "" {
		bin, err := exec.LookPath("buildctl")
		if err != nil {
			return nil, errors.New("builder.addr is set but buildctl is not on PATH")
		}
		cmd = exec.CommandContext(ctx, bin, append([]string{"--addr", cfg.Addr}, args(req.ContextDir, req.OutDir)...)...)
	} else {
		var err error
		if rt, err = container.Runtime(cfg.Runtime); err != nil {
			return nil, err
		}
		run := []string{"run", "--rm", "--privileged",
			"--mount", bind(req.ContextDir, "/ctx", true),
			"--mount", bind(req.OutDir, "/out", false),
		}
		run = append(run, containerOptions(cfg)...)
		if !req.NoCache && cfg.CacheVolume != "" {
			run = append(run, "--mount", "type=volume,source="+cfg.CacheVolume+",target=/var/lib/buildkit")
		}
		if cfg.WriteAuth != nil && len(req.Registries) > 0 {
			authDir := filepath.Join(req.OutDir, ".auth")
			if err := cfg.WriteAuth(filepath.Join(authDir, "config.json"), req.Registries); err != nil {
				return nil, fmt.Errorf("preparing registry credentials: %w", err)
			}
			defer func() { _ = os.RemoveAll(authDir) }()
			run = append(run, "--mount", bind(authDir, "/root/.docker", true))
		}
		// Hand the output back to the invoking user (rootful runtimes on Linux).
		script := `buildctl-daemonless.sh "$@"`
		if uid := os.Getuid(); uid > 0 && runtime.GOOS == "linux" {
			script += fmt.Sprintf(` && chown -R %d:%d /out/image /out/metadata.json`, uid, os.Getgid())
		}
		run = append(run, "--entrypoint", "sh", registry.Qualify(req.BuildKitImage), "-c", script, "--")
		run = append(run, args("/ctx", "/out")...)
		cmd = exec.CommandContext(ctx, rt, run...)
	}
	// The runtime's own errors come before BuildKit's output: keep the
	// start of stderr to tell a path the runtime can't see from a failed
	// build.
	head := &headWriter{max: 4096}
	cmd.Stdout = cfg.Stdout
	cmd.Stderr = io.MultiWriter(writerOrDiscard(cfg.Stderr), head)
	if err := cmd.Run(); err != nil {
		if rt != "" {
			if nse := NotShared(rt, head.String()); nse != nil {
				return nil, nse
			}
		}
		return nil, fmt.Errorf("build failed: %w", err)
	}

	b, err := os.ReadFile(meta)
	if err != nil {
		return nil, fmt.Errorf("reading build metadata: %w", err)
	}
	var md struct {
		Digest string `json:"containerimage.digest"`
	}
	if err := json.Unmarshal(b, &md); err != nil {
		return nil, fmt.Errorf("parsing build metadata: %w", err)
	}
	if md.Digest == "" {
		return nil, errors.New("build metadata has no containerimage.digest")
	}
	return &Result{LayoutDir: layoutDir, Digest: md.Digest}, nil
}

// containerOptions are the run options for the BuildKit container's network
// and buildkitd configuration. buildctl-daemonless.sh passes BUILDKITD_FLAGS
// to buildkitd.
func containerOptions(cfg Config) []string {
	var o []string
	if cfg.Network != "" {
		o = append(o, "--network", cfg.Network)
	}
	if cfg.BuildkitdConfig != "" {
		o = append(o, "--mount", bind(cfg.BuildkitdConfig, buildkitdConfig, true),
			"--env", "BUILDKITD_FLAGS=--config="+buildkitdConfig)
	}
	return o
}

// bind formats a --mount bind spec; unlike -v it tolerates ':' in host paths.
// The source is the path with its symbolic links resolved, since a
// container runtime in a VM (a podman machine, Docker Desktop) sees only
// the host directories shared with it, by their real paths: on macOS /tmp
// is /private/tmp, which a podman machine shares, while the VM's own /tmp
// is another directory.
func bind(src, dst string, readonly bool) string {
	m := "type=bind,source=" + HostPath(src) + ",target=" + dst
	if readonly {
		m += ",readonly"
	}
	return m
}

// HostPath is p as a container runtime should be given it: absolute, with
// symbolic links resolved (p itself when it can't be resolved).
func HostPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		return real
	}
	return abs
}

// NotSharedError is a path the container runtime couldn't see: it runs in
// a VM (a podman machine, Docker Desktop) that shares only some host
// directories with it.
type NotSharedError struct {
	Runtime string // docker or podman
	Path    string
}

func (e *NotSharedError) Error() string {
	if e.Runtime == "podman" {
		return fmt.Sprintf("podman can't see %s, which the build mounts into its BuildKit container: a podman machine shares only some host directories with its VM (your home directory, by default; podman machine inspect lists them), so build from a directory under one of them and keep --out there, or share the path with the machine (podman machine init --volume)", e.Path)
	}
	return fmt.Sprintf("%s can't see %s, which the build mounts into its BuildKit container: the runtime's VM shares only some host directories (Docker Desktop: Settings → Resources → File sharing), so build from a directory it shares and keep --out there, or share the path", e.Runtime, e.Path)
}

var (
	// podman: Error: statfs /tmp/x/context: no such file or directory
	podmanNotShared = regexp.MustCompile(`statfs (\S+): no such file or directory`)
	// Docker Desktop: Mounts denied: The path /x is not shared from the host and is not known to Docker.
	dockerNotShared = regexp.MustCompile(`(?s)Mounts denied:.*?[Tt]he path (\S+) is not shared`)
)

// NotShared recognizes the runtime's message for a bind mount source it
// can't see, in the start of its stderr, and returns it as an error that
// names the cause and the fix; nil for any other failure.
func NotShared(runtimeBin, stderr string) error {
	rt := "docker"
	if strings.Contains(filepath.Base(runtimeBin), "podman") {
		rt = "podman"
	}
	for _, re := range []*regexp.Regexp{podmanNotShared, dockerNotShared} {
		if m := re.FindStringSubmatch(stderr); m != nil {
			return &NotSharedError{Runtime: rt, Path: strings.TrimSuffix(m[1], ".")}
		}
	}
	return nil
}

// headWriter keeps the first max bytes written to it.
type headWriter struct {
	max int
	buf []byte
}

func (h *headWriter) Write(p []byte) (int, error) {
	if room := h.max - len(h.buf); room > 0 {
		h.buf = append(h.buf, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

func (h *headWriter) String() string { return string(h.buf) }

func writerOrDiscard(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	return w
}
