package factory

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"

	"github.com/northcutted/clearcutt-factory/internal/manifest"
	"github.com/northcutted/clearcutt-factory/internal/registry"
)

// TestStackPushSignsOnce: stack push signs with the stack key, and pushing
// an unchanged stack the org's stack signer signed only moves the tag.
func TestStackPushSignsOnce(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ctx := context.Background()
	dir := t.TempDir()
	stack := "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Stack\nmetadata: {name: go}\nspec:\n  build: golang:1\n  run: cgr.dev/chainguard/static:latest\n  steps: [{run: go build -o /out/app .}]\n"
	for n, body := range map[string]string{
		"factory.org.yaml": "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nsigning:\n  mode: key\n  key: keys/images.key\n  stackKey: keys/stacks.key\n  stacks: {key: keys/stacks.pub}\n",
		"go.yaml":          stack,
	} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cosign := newFakeCosign(t, "--key "+filepath.Join(dir, "keys/stacks.pub"))
	var out bytes.Buffer
	opts := Options{Stdout: &out, Stderr: &out}
	file := filepath.Join(dir, "go.yaml")
	ref := host + "/stacks/go:1"
	digest := func() string {
		t.Helper()
		d, err := registry.Digest(ctx, ref)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}

	// The first push signs with signing.stackKey, not signing.key.
	if err := StackPushWith(ctx, opts, file, StackPushOptions{Ref: ref}); err != nil {
		t.Fatal(err)
	}
	pushed := host + "/stacks/go@" + digest()
	if c := cosign.calls(); len(c) != 1 || c[0] != "sign "+pushed+" --key "+filepath.Join(dir, "keys/stacks.key")+" --yes" {
		t.Fatalf("first push: cosign calls %q", c)
	}
	signed, err := os.OpenFile(cosign.path+".signed", os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = signed.WriteString(pushed + "\n")
	_ = signed.Close()

	// The tag moves elsewhere; pushing the same stack again moves it back,
	// checks the signature, and doesn't sign again (nor with --key).
	if _, err := registry.PushFile(ctx, ref, manifest.StackArtifactType, "stack.yaml", []byte("other")); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := StackPushWith(ctx, opts, file, StackPushOptions{Ref: ref, Key: "awskms:///alias/other"}); err != nil {
		t.Fatal(err)
	}
	if c := cosign.calls(); len(c) != 1 || !strings.HasPrefix(c[0], "verify ") || !strings.HasSuffix(c[0], " "+pushed) {
		t.Errorf("unchanged push: cosign calls %q", c)
	}
	if host+"/stacks/go@"+digest() != pushed || !strings.Contains(out.String(), "already published at "+pushed+"; moved 1") {
		t.Errorf("unchanged push didn't move the tag back:\n%s", out.String())
	}

	// A stack pushed unsigned is signed when pushed again with signing on.
	changed := strings.Replace(stack, "golang:1", "golang:2", 1)
	if err := os.WriteFile(file, []byte(changed), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := StackPushWith(ctx, opts, file, StackPushOptions{Ref: ref, NoSign: true}); err != nil {
		t.Fatal(err)
	}
	if c := cosign.calls(); len(c) != 0 {
		t.Errorf("--no-sign: cosign calls %q", c)
	}
	if err := StackPushWith(ctx, opts, file, StackPushOptions{Ref: ref, Key: "awskms:///alias/stacks"}); err != nil {
		t.Fatal(err)
	}
	pushed = host + "/stacks/go@" + digest()
	if c := cosign.calls(); len(c) != 2 || !strings.HasPrefix(c[0], "verify ") || c[1] != "sign "+pushed+" --key awskms:///alias/stacks --yes" {
		t.Errorf("unsigned, then --key: cosign calls %q", c)
	}

	if err := StackPushWith(ctx, opts, file, StackPushOptions{Ref: ref, Key: "k", NoSign: true}); err == nil {
		t.Error("--key with --no-sign was accepted")
	}
}

// TestStackSigner: who stack push signs as.
func TestStackSigner(t *testing.T) {
	key := &manifest.Org{Signing: manifest.Signing{Mode: "key", Key: "images.key", Args: []string{"--signing-config", "sc.json"}}}
	keyless := &manifest.Org{Signing: manifest.Signing{Mode: "keyless"}}
	none := &manifest.Org{Signing: manifest.Signing{Mode: "none"}}
	withStackKey := &manifest.Org{Signing: manifest.Signing{Mode: "key", Key: "images.key", StackKey: "stacks.key"}}
	for _, c := range []struct {
		name      string
		org       *manifest.Org
		so        StackPushOptions
		mode, key string // empty mode: no signature
	}{
		{"key mode", key, StackPushOptions{}, "key", "images.key"},
		{"stack key", withStackKey, StackPushOptions{}, "key", "stacks.key"},
		{"--key over the stack key", withStackKey, StackPushOptions{Key: "flag.key"}, "key", "flag.key"},
		{"keyless", keyless, StackPushOptions{}, "keyless", ""},
		{"--key in keyless mode", keyless, StackPushOptions{Key: "flag.key"}, "key", "flag.key"},
		{"signing off", none, StackPushOptions{}, "", ""},
		{"--key with signing off", none, StackPushOptions{Key: "flag.key"}, "key", "flag.key"},
		{"--no-sign", key, StackPushOptions{NoSign: true}, "", ""},
	} {
		s := stackSigner(Options{}, c.org, c.so)
		switch {
		case c.mode == "" && s != nil:
			t.Errorf("%s: signs (%+v)", c.name, s)
		case c.mode != "" && (s == nil || s.Mode != c.mode || (c.mode == "key" && s.Key != c.key) || strings.Join(s.Args, " ") != strings.Join(c.org.Signing.Args, " ")):
			t.Errorf("%s: %+v, want mode %s key %s", c.name, s, c.mode, c.key)
		}
	}
}
