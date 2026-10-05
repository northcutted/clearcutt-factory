package native

import (
	"context"
	"strings"
	"testing"

	"github.com/northcutted/declarative-image-factory/internal/lock"
)

const aptOut = `### os
debian 13
### sources
http://snapshot.debian.org/archive/debian-security/20261003T000000Z/
http://snapshot.debian.org/archive/debian/20261003T000000Z/
### simulate
NOTE: This is only a simulation!
Inst libonig5 (6.9.9-1+b1 Debian:13.7/stable [arm64])
Inst git-man (1:2.47.3-0+deb13u1 Debian:13.7/stable, Debian-Security:13/stable-security [all])
Inst libc6 [2.41-11] (2.41-12 Debian:13.7/stable [arm64])
Conf libonig5 (6.9.9-1+b1 Debian:13.7/stable [arm64])
### uris
'http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/libo/libonig/libonig5_6.9.9-1%2bb1_arm64.deb' libonig5_6.9.9-1+b1_arm64.deb 170000 MD5Sum:00
'http://snapshot.debian.org/archive/debian-security/20261003T000000Z/pool/updates/main/g/git/git-man_2.47.3-0%2bdeb13u1_all.deb' git-man_1%3a2.47.3-0+deb13u1_all.deb 2000000 MD5Sum:11
'http://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/g/glibc/libc6_2.41-12_arm64.deb' libc6_2.41-12_arm64.deb 2700000 MD5Sum:22
### records
Package: libonig5
Source: libonig (6.9.9-1)
Version: 6.9.9-1+b1
Architecture: arm64
Description: regular expressions library
 continuation line: ignored
Filename: pool/main/libo/libonig/libonig5_6.9.9-1+b1_arm64.deb
SHA256: aaaa

Package: git-man
Source: git
Version: 1:2.47.3-0+deb13u1
Architecture: all
Filename: pool/updates/main/g/git/git-man_2.47.3-0+deb13u1_all.deb
SHA256: bbbb

Package: libc6
Source: glibc
Version: 2.41-12
Architecture: arm64
Filename: pool/main/g/glibc/libc6_2.41-12_arm64.deb
SHA256: cccc
`

func TestParseAPT(t *testing.T) {
	var gotArgs []string
	run := func(_ context.Context, image, platform, script string, args ...string) ([]byte, error) {
		gotArgs = args
		return []byte(aptOut), nil
	}
	res, err := ResolveAPT(context.Background(), run, "debian@sha256:x", "linux/arm64", "20261003T000000Z", []string{"jq"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(gotArgs, " ") != "20261003T000000Z jq" {
		t.Errorf("script args: %v", gotArgs)
	}
	if res.Distro != "debian-13" || res.Snapshot != "20261003T000000Z" || len(res.Repositories) != 2 {
		t.Errorf("result: %+v", res)
	}
	want := map[string]lock.Package{
		"git-man":  {Name: "git-man", Version: "1:2.47.3-0+deb13u1", Arch: "all", SHA256: "bbbb", Origin: "git", Filename: "git-man_2.47.3-0+deb13u1_all.deb", URL: "https://snapshot.debian.org/archive/debian-security/20261003T000000Z/pool/updates/main/g/git/git-man_2.47.3-0%2bdeb13u1_all.deb"},
		"libc6":    {Name: "libc6", Version: "2.41-12", Arch: "arm64", SHA256: "cccc", Origin: "glibc", Filename: "libc6_2.41-12_arm64.deb"},
		"libonig5": {Name: "libonig5", Version: "6.9.9-1+b1", Arch: "arm64", SHA256: "aaaa", Origin: "libonig", Filename: "libonig5_6.9.9-1+b1_arm64.deb"},
	}
	if len(res.Packages) != 3 {
		t.Fatalf("packages: %+v", res.Packages)
	}
	for _, p := range res.Packages {
		w := want[p.Name]
		if p.Version != w.Version || p.Arch != w.Arch || p.SHA256 != w.SHA256 || p.Origin != w.Origin || p.Filename != w.Filename {
			t.Errorf("%s: got %+v", p.Name, p)
		}
		if w.URL != "" && p.URL != w.URL {
			t.Errorf("%s url: %s", p.Name, p.URL)
		}
		if !strings.HasPrefix(p.URL, "https://snapshot.debian.org/") {
			t.Errorf("%s should download from the snapshot over https: %s", p.Name, p.URL)
		}
	}
}

func TestParseAPTUbuntuUsesLaunchpad(t *testing.T) {
	out := strings.NewReplacer(
		"debian 13", "ubuntu 24.04",
		"http://snapshot.debian.org/archive/debian/20261003T000000Z", "http://ports.ubuntu.com/ubuntu-ports",
		"http://snapshot.debian.org/archive/debian-security/20261003T000000Z", "http://ports.ubuntu.com/ubuntu-ports",
	).Replace(aptOut)
	res, err := parseAPT([]byte(out), "20261003T000000Z")
	if err != nil {
		t.Fatal(err)
	}
	if res.Snapshot != "" {
		t.Errorf("ubuntu should not record a snapshot: %q", res.Snapshot)
	}
	for _, p := range res.Packages {
		if !strings.HasPrefix(p.URL, "https://launchpad.net/ubuntu/+archive/primary/+files/") || !strings.HasSuffix(p.URL, "_"+p.Arch+".deb") {
			t.Errorf("%s: %s", p.Name, p.URL)
		}
	}
	if len(res.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", res.Warnings)
	}
}

func TestParseAPTMissingRecord(t *testing.T) {
	out := strings.Replace(aptOut, "SHA256: cccc", "", 1)
	if _, err := parseAPT([]byte(out), "x"); err == nil || !strings.Contains(err.Error(), "SHA256") {
		t.Fatalf("expected missing sha256 error, got %v", err)
	}
}

const dnfOut = `### os
fedora 44
### rpms
1111	jq	0	1.8.1	3.fc44	aarch64	jq-1.8.1-3.fc44.src.rpm	MIT AND ICU AND CC-BY-3.0	RSA/SHA256, Thu 01 Oct 2026 10:00:00 AM UTC, Key ID 809A8D7C6D9F90A6
2222	oniguruma	0	6.9.10	4.fc44	aarch64	oniguruma-6.9.10-4.fc44.src.rpm	BSD-2-Clause	RSA/SHA256, Thu 01 Oct 2026 10:00:00 AM UTC, Key ID 809a8d7c6d9f90a6
3333	python3-libs	1	3.14.1	2.fc44	aarch64	python3.14-3.14.1-2.fc44.src.rpm	Python-2.0.1	RSA/SHA256, Thu 01 Oct 2026 10:00:00 AM UTC, Key ID 809a8d7c6d9f90a6
### signatures
/var/cache/libdnf5/updates-1/packages/jq-1.8.1-3.fc44.aarch64.rpm: digests signatures OK
/var/cache/libdnf5/fedora-1/packages/oniguruma-6.9.10-4.fc44.aarch64.rpm: digests signatures OK
/var/cache/libdnf5/fedora-1/packages/python3-libs-3.14.1-2.fc44.aarch64.rpm: digests signatures OK
### urls
http://mirror.example/fedora/linux/updates/44/Everything/aarch64/Packages/j/jq-1.8.1-3.fc44.aarch64.rpm
https://mirror.example/fedora/linux/releases/44/Everything/aarch64/os/Packages/o/oniguruma-6.9.10-4.fc44.aarch64.rpm
https://mirror.example/fedora/linux/releases/44/Everything/aarch64/os/Packages/p/python3-libs-3.14.1-2.fc44.aarch64.rpm
`

func TestParseDNFFedoraUsesKoji(t *testing.T) {
	res, err := parseDNF([]byte(dnfOut))
	if err != nil {
		t.Fatal(err)
	}
	if res.Distro != "fedora-44" || len(res.Packages) != 3 {
		t.Fatalf("result: %+v", res)
	}
	byName := map[string]lock.Package{}
	for _, p := range res.Packages {
		byName[p.Name] = p
	}
	py := byName["python3-libs"]
	if py.Version != "1:3.14.1-2.fc44" || py.Origin != "python3.14" ||
		py.URL != "https://kojipkgs.fedoraproject.org/packages/python3.14/3.14.1/2.fc44/data/signed/6d9f90a6/aarch64/python3-libs-3.14.1-2.fc44.aarch64.rpm" {
		t.Errorf("python3-libs: %+v", py)
	}
	if jq := byName["jq"]; jq.SHA256 != "1111" || jq.License != "MIT AND ICU AND CC-BY-3.0" || jq.Filename != "jq-1.8.1-3.fc44.aarch64.rpm" {
		t.Errorf("jq: %+v", jq)
	}
}

func TestParseDNFAmazonLinuxCleansPath(t *testing.T) {
	out := `### os
amzn 2023
### rpms
4444	jq	0	1.7.1	50.amzn2023	aarch64	jq-1.7.1-50.amzn2023.src.rpm	MIT
### signatures
/var/cache/dnf/amazonlinux-1/packages/jq-1.7.1-50.amzn2023.aarch64.rpm: digests signatures OK
### urls
https://cdn.amazonlinux.com/al2023/core/guids/abc/aarch64/../../../../blobstore/def/jq-1.7.1-50.amzn2023.aarch64.rpm
`
	res, err := parseDNF([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if u := res.Packages[0].URL; u != "https://cdn.amazonlinux.com/al2023/blobstore/def/jq-1.7.1-50.amzn2023.aarch64.rpm" {
		t.Errorf("url: %s", u)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("amazon linux keeps old builds; no warning expected: %v", res.Warnings)
	}
	if len(res.Repositories) != 1 || res.Repositories[0] != "https://cdn.amazonlinux.com/al2023/core/guids/abc/aarch64" {
		t.Errorf("repositories: %v", res.Repositories)
	}
}

func TestParseDNFRejectsBadSignature(t *testing.T) {
	out := strings.Replace(dnfOut, "oniguruma-6.9.10-4.fc44.aarch64.rpm: digests signatures OK", "oniguruma-6.9.10-4.fc44.aarch64.rpm: digests SIGNATURES NOT OK", 1)
	if _, err := parseDNF([]byte(out)); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected signature error, got %v", err)
	}
}

func TestEscapePlus(t *testing.T) {
	for in, want := range map[string]string{
		"https://cdn.example/blobstore/abc/perl-Text-Tabs+Wrap-1.noarch.rpm":          "https://cdn.example/blobstore/abc/perl-Text-Tabs%2BWrap-1.noarch.rpm",
		"https://snapshot.debian.org/pool/libonig5_6.9.9-1%2bb1_arm64.deb":            "https://snapshot.debian.org/pool/libonig5_6.9.9-1%2bb1_arm64.deb",
		"https://kojipkgs.fedoraproject.org/packages/gcc/15/1/x/libstdc++-15-1.x.rpm": "https://kojipkgs.fedoraproject.org/packages/gcc/15/1/x/libstdc%2B%2B-15-1.x.rpm",
	} {
		if got := escapePlus(in); got != want {
			t.Errorf("escapePlus(%s) = %s", in, got)
		}
	}
}

func TestDetectManager(t *testing.T) {
	for osr, want := range map[string]string{
		"ID=debian\nVERSION_ID=\"13\"\n":             lock.ManagerAPT,
		"ID=ubuntu\nID_LIKE=debian\n":                lock.ManagerAPT,
		"ID=\"rhel\"\nID_LIKE=\"fedora\"\n":          lock.ManagerDNF,
		"ID=\"amzn\"\nID_LIKE=\"fedora\"\n":          lock.ManagerDNF,
		"ID=rocky\nID_LIKE=\"rhel centos fedora\"\n": lock.ManagerDNF,
		"ID=wolfi\n": lock.ManagerAPK,
		"ID=arch\n":  "",
	} {
		if got := DetectManager(OSRelease([]byte(osr))); got != want {
			t.Errorf("%q: got %q, want %q", osr, got, want)
		}
	}
}
