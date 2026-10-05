package registry

import (
	"context"
	"io"
	"log"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func TestQualify(t *testing.T) {
	for in, want := range map[string]string{
		"amazonlinux:2023": "docker.io/library/amazonlinux:2023",
		"amazonlinux:2023@sha256:5b29412077a463b4a3a8fbc99a8cdf4b929f38a3ecc8dac10328d8f36b0099b8": "docker.io/library/amazonlinux:2023@sha256:5b29412077a463b4a3a8fbc99a8cdf4b929f38a3ecc8dac10328d8f36b0099b8",
		"moby/buildkit@sha256:cec9f139f45e93c5c69c60f8b07cfad9f43f4ef6b6a6cd917527fea5ff2e3dea":    "docker.io/moby/buildkit@sha256:cec9f139f45e93c5c69c60f8b07cfad9f43f4ef6b6a6cd917527fea5ff2e3dea",
		"cgr.dev/chainguard/wolfi-base:latest":                                                     "cgr.dev/chainguard/wolfi-base:latest",
		"localhost:5555/e2e/x:latest":                                                              "localhost:5555/e2e/x:latest",
	} {
		if got := Qualify(in); got != want {
			t.Errorf("Qualify(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestPlatformRef(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	var adds []mutate.IndexAddendum
	for _, arch := range []string{"amd64", "arm64"} {
		img, err := random.Image(32, 1)
		if err != nil {
			t.Fatal(err)
		}
		adds = append(adds, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: arch}}})
	}
	idx := mutate.AppendManifests(empty.Index, adds...)
	ref, _ := name.ParseReference(host + "/base:latest")
	if err := remote.WriteIndex(ref, idx); err != nil {
		t.Fatal(err)
	}
	d, _ := idx.Digest()
	im, _ := idx.IndexManifest()
	got, err := PlatformRef(context.Background(), host+"/base:latest@"+d.String(), "linux/arm64")
	if err != nil {
		t.Fatal(err)
	}
	if want := host + "/base@" + im.Manifests[1].Digest.String(); got != want {
		t.Errorf("PlatformRef = %s, want %s", got, want)
	}
	single := host + "/base@" + im.Manifests[0].Digest.String()
	if got, err := PlatformRef(context.Background(), single, "linux/amd64"); err != nil || got != single {
		t.Errorf("single image: %s, %v", got, err)
	}
	if _, err := PlatformRef(context.Background(), host+"/base:latest", "linux/s390x"); err == nil {
		t.Error("expected an error for a missing platform")
	}
}
