package apk

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	less := [][2]string{
		{"1.0", "1.0.1"},
		{"1.2.9", "1.2.10"},
		{"1.0-r1", "1.0-r2"},
		{"1.0-r9", "1.0.1-r0"},
		{"1.0_rc1", "1.0"},
		{"1.0_alpha2", "1.0_beta1"},
		{"1.0", "1.0_p1"},
		{"1.0a", "1.0b"},
		{"5.2.37-r0", "5.2.37-r33"},
		{"1.3.2.1_rc20260601-r0", "1.3.2.1"},
		{"6.6.20260101-r0", "6.6.20260926-r0"},
	}
	for _, c := range less {
		if CompareVersions(c[0], c[1]) >= 0 || CompareVersions(c[1], c[0]) <= 0 {
			t.Errorf("expected %s < %s", c[0], c[1])
		}
	}
	if CompareVersions("1.2.3-r4", "1.2.3-r4") != 0 {
		t.Error("equal versions should compare equal")
	}
}

func TestSatisfies(t *testing.T) {
	cases := []struct {
		v, op, want string
		ok          bool
	}{
		{"1.2-r0", "", "", true},
		{"1.2-r0", ">=", "1.1", true},
		{"1.2-r0", "<", "1.1", false},
		{"1.2-r0", "=", "1.2-r0", true},
		{"1.2.5-r0", "~", "1.2", true},
		{"1.3-r0", "~", "1.2", false},
	}
	for _, c := range cases {
		if got := Satisfies(c.v, c.op, c.want); got != c.ok {
			t.Errorf("Satisfies(%s %s %s) = %v", c.v, c.op, c.want, got)
		}
	}
}

func TestSplitDep(t *testing.T) {
	for in, want := range map[string][3]string{
		"bash":          {"bash", "", ""},
		"so:libc.so.6":  {"so:libc.so.6", "", ""},
		"glibc>=2.40":   {"glibc", ">=", "2.40"},
		"cmd:sh=1.2-r0": {"cmd:sh", "=", "1.2-r0"},
		"!conflict":     {"!conflict", "", ""},
	} {
		n, op, v := splitDep(in)
		if [3]string{n, op, v} != want {
			t.Errorf("splitDep(%q) = %q %q %q", in, n, op, v)
		}
	}
}

const testIndex = `P:bash
V:5.2-r1
A:aarch64
C:Q1old=
D:so:libc.so.6 so:libtinfo.so.6

P:bash
V:5.2-r2
A:aarch64
C:Q1new=
L:GPL-3.0-or-later
D:so:libc.so.6 so:libtinfo.so.6
p:cmd:bash=5.2-r2

P:glibc
V:2.40-r1
A:aarch64
C:Q1g=
p:so:libc.so.6=6

P:musl-compat
V:1-r0
A:aarch64
C:Q1m=
k:-10
p:so:libc.so.6=6

P:ncurses
V:6.5-r1
A:aarch64
C:Q1n=
D:glibc>=2.40
p:so:libtinfo.so.6=6

P:bash-doc
V:5.2-r2
A:aarch64
C:Q1d=
i:bash=5.2-r2 docs

P:bash-completion
V:2.11-r0
A:aarch64
C:Q1c=
i:bash
`

func parseTest(t *testing.T) *Index {
	t.Helper()
	pkgs, err := ParseIndex(strings.NewReader(testIndex))
	if err != nil {
		t.Fatal(err)
	}
	return NewIndex("aarch64", pkgs)
}

func TestResolve(t *testing.T) {
	idx := parseTest(t)
	got, err := idx.Resolve([]string{"bash"})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range got {
		names = append(names, p.Name+"="+p.Version)
	}
	// newest bash; glibc wins the so:libc provider tie on priority; ncurses
	// via so:libtinfo; bash-completion via install_if; bash-doc needs "docs".
	want := "bash=5.2-r2 bash-completion=2.11-r0 glibc=2.40-r1 ncurses=6.5-r1"
	if strings.Join(names, " ") != want {
		t.Fatalf("got %s\nwant %s", strings.Join(names, " "), want)
	}
}

func TestResolveExplicitProviderWins(t *testing.T) {
	idx := parseTest(t)
	got, err := idx.Resolve([]string{"musl-compat", "bash"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range got {
		if p.Name == "glibc" {
			// ncurses needs glibc>=2.40 by name, so glibc is still selected;
			// so:libc.so.6 itself is satisfied by the explicit musl-compat.
			return
		}
	}
	t.Fatal("glibc should be pulled in by ncurses' named dependency")
}

func TestResolveMissing(t *testing.T) {
	idx := parseTest(t)
	if _, err := idx.Resolve([]string{"nope"}); err == nil || !strings.Contains(err.Error(), "nothing provides nope") {
		t.Fatalf("expected missing package error, got %v", err)
	}
}

func TestParseIndexArchive(t *testing.T) {
	// Real APKINDEX.tar.gz files are a signature gzip stream followed by the
	// index gzip stream; the tar entries span both.
	var buf bytes.Buffer
	stream := func(files map[string]string, end bool) {
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		for name, body := range files {
			_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))})
			_, _ = tw.Write([]byte(body))
		}
		if end {
			_ = tw.Close()
		} else {
			_ = tw.Flush()
		}
		_ = gz.Close()
	}
	stream(map[string]string{".SIGN.RSA.key.rsa.pub": "sig"}, false)
	stream(map[string]string{"APKINDEX": testIndex}, true)

	pkgs, err := ParseIndexArchive(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 7 || pkgs[1].License != "GPL-3.0-or-later" || pkgs[3].ProviderPrio != -10 {
		t.Fatalf("unexpected parse: %d packages", len(pkgs))
	}
}

func TestVerifyIndexSignature(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	// Second stream: the index itself.
	var index bytes.Buffer
	gz := gzip.NewWriter(&index)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "APKINDEX", Mode: 0o644, Size: int64(len(testIndex))})
	_, _ = tw.Write([]byte(testIndex))
	_ = tw.Close()
	_ = gz.Close()

	build := func(signed []byte, keyName string) []byte {
		sum := sha256.Sum256(signed)
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		gz := gzip.NewWriter(&out)
		tw := tar.NewWriter(gz)
		_ = tw.WriteHeader(&tar.Header{Name: ".SIGN.RSA256." + keyName, Mode: 0o644, Size: int64(len(sig))})
		_, _ = tw.Write(sig)
		_ = tw.Flush()
		_ = gz.Close()
		out.Write(index.Bytes())
		return out.Bytes()
	}
	keys := map[string][]byte{"test.rsa.pub": pubPEM}

	if err := VerifyIndexSignature(build(index.Bytes(), "test.rsa.pub"), keys); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if err := VerifyIndexSignature(build([]byte("something else"), "test.rsa.pub"), keys); err == nil {
		t.Error("signature over other data accepted")
	}
	if err := VerifyIndexSignature(build(index.Bytes(), "unknown.rsa.pub"), keys); err == nil || !strings.Contains(err.Error(), "unknown.rsa.pub") {
		t.Errorf("unknown key: %v", err)
	}
}
