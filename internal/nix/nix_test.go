package nix

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A real narinfo from cache.nixos.org, signed with its production key.
const ripgrepNarInfo = `StorePath: /nix/store/vmp6hi5xhn5awg76jk3zk0012hig1ds8-ripgrep-14.1.1
URL: nar/05q6q1qbfh4hx0xbrchx8zjhbrbgbawab22dyz1kiwqhcknj8bhb.nar.xz
Compression: xz
FileHash: sha256:05q6q1qbfh4hx0xbrchx8zjhbrbgbawab22dyz1kiwqhcknj8bhb
FileSize: 1583664
NarHash: sha256:0k9z0s8mdggnsdpvd45xxk8iyfm6y2jijn3vnrihfn2x2s30gdnv
NarSize: 6612248
References: cf1a53iqg6ncnygl698c4v0l8qam5a2q-gcc-14.3.0-lib i3ibgfskl99qd8rslafbpaa1dmxdzh1z-glibc-2.40-66 n6vl6ni6zxxgh4163cqnjf8p0n7yah0d-pcre2-10.44
Deriver: 6gj278nflwyyvg6q8c5y5dc7kh6zd0jv-ripgrep-14.1.1.drv
Sig: cache.nixos.org-1:e9bVc8CAY+OwJv/njv+k/RRWBJpTSOLATvG2OtREui8/CKxkk4mQsfYecATXJprnS/m9QybKtem81S/mxn4jAw==
`

func TestVerifyRealSignature(t *testing.T) {
	ni, err := ParseNarInfo(strings.NewReader(ripgrepNarInfo))
	if err != nil {
		t.Fatal(err)
	}
	if err := ni.Verify([]string{DefaultKey}); err != nil {
		t.Fatalf("real signature should verify: %v", err)
	}
	tampered, _ := ParseNarInfo(strings.NewReader(strings.Replace(ripgrepNarInfo, "NarSize: 6612248", "NarSize: 6612249", 1)))
	if err := tampered.Verify([]string{DefaultKey}); err == nil {
		t.Fatal("tampered narinfo should not verify")
	}
	if err := ni.Verify([]string{"other-key:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="}); err == nil {
		t.Fatal("signature under a different key name should not be accepted")
	}
}

func TestDecodeBase32(t *testing.T) {
	// nix hash convert --hash-algo sha256 --to base16 sha256:0k9z0s8m…
	b, err := DecodeBase32("0k9z0s8mdggnsdpvd45xxk8iyfm6y2jijn3vnrihfn2x2s30gdnv")
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(b); got != "dbb60786165d580763b67b5819a5f0a63a1fd1ecbd90b66fd3f6bd5691063f4d" {
		t.Fatalf("got %s", got)
	}
	if _, err := DecodeBase32("e"); err == nil {
		t.Error("'e' is not in nix's alphabet")
	}
}

func TestNameVersion(t *testing.T) {
	for p, want := range map[string][2]string{
		"/nix/store/vmp6hi5xhn5awg76jk3zk0012hig1ds8-ripgrep-14.1.1":         {"ripgrep", "14.1.1"},
		"/nix/store/i3ibgfskl99qd8rslafbpaa1dmxdzh1z-glibc-2.40-66":          {"glibc", "2.40-66"},
		"/nix/store/cf1a53iqg6ncnygl698c4v0l8qam5a2q-gcc-14.3.0-lib":         {"gcc", "14.3.0"},
		"/nix/store/q1nq6fylbczrsj7k9bqc9dzf660q63v3-bash-interactive-5.3p9": {"bash-interactive", "5.3p9"},
		"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-tzdata":                 {"tzdata", ""},
	} {
		n, v := NameVersion(p)
		if n != want[0] || v != want[1] {
			t.Errorf("%s: got %s %s", p, n, v)
		}
	}
}

func TestClosure(t *testing.T) {
	// A fake cache with an unsigned path: Closure must refuse it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/vmp6hi5xhn5awg76jk3zk0012hig1ds8.narinfo":
			_, _ = fmt.Fprint(w, ripgrepNarInfo)
		case "/i3ibgfskl99qd8rslafbpaa1dmxdzh1z.narinfo":
			_, _ = fmt.Fprint(w, "StorePath: /nix/store/i3ibgfskl99qd8rslafbpaa1dmxdzh1z-glibc-2.40-66\nNarHash: sha256:00\nNarSize: 1\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	_, err := Closure(context.Background(), srv.Client(), srv.URL, []string{DefaultKey}, "/nix/store/vmp6hi5xhn5awg76jk3zk0012hig1ds8-ripgrep-14.1.1")
	if err == nil {
		t.Fatal("expected an error for unsigned or missing references")
	}
	if !strings.Contains(err.Error(), "signature") && !strings.Contains(err.Error(), "binary cache") {
		t.Fatalf("unexpected error: %v", err)
	}
}
