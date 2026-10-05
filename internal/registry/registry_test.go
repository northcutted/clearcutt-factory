package registry

import "testing"

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
