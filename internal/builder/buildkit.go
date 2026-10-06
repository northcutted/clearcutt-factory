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
}

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
	if cfg.Addr != "" {
		bin, err := exec.LookPath("buildctl")
		if err != nil {
			return nil, errors.New("builder.addr is set but buildctl is not on PATH")
		}
		cmd = exec.CommandContext(ctx, bin, append([]string{"--addr", cfg.Addr}, args(req.ContextDir, req.OutDir)...)...)
	} else {
		rt, err := container.Runtime(cfg.Runtime)
		if err != nil {
			return nil, err
		}
		run := []string{"run", "--rm", "--privileged",
			"--mount", bind(req.ContextDir, "/ctx", true),
			"--mount", bind(req.OutDir, "/out", false),
		}
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
	cmd.Stdout, cmd.Stderr = cfg.Stdout, cfg.Stderr
	if err := cmd.Run(); err != nil {
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

// bind formats a --mount bind spec; unlike -v it tolerates ':' in host paths.
func bind(src, dst string, readonly bool) string {
	m := "type=bind,source=" + src + ",target=" + dst
	if readonly {
		m += ",readonly"
	}
	return m
}
