package rebase

import (
	"archive/tar"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/google/go-containerregistry/pkg/v1/validate"
)

// f is a tar entry for test layers: "dir/", "link -> target", ".wh.name",
// or a regular file with content.
type f struct{ name, content string }

func layer(t *testing.T, files ...f) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, x := range files {
		h := &tar.Header{Name: x.name, Mode: 0o644, ModTime: time.Unix(1700000000, 0)}
		switch {
		case strings.HasSuffix(x.name, "/"):
			h.Typeflag, h.Mode = tar.TypeDir, 0o755
		case strings.Contains(x.name, " -> "):
			h.Name, h.Linkname, _ = strings.Cut(x.name, " -> ")
			h.Typeflag = tar.TypeSymlink
		default:
			h.Typeflag, h.Size = tar.TypeReg, int64(len(x.content))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			_, _ = tw.Write([]byte(x.content))
		}
	}
	_ = tw.Close()
	b := buf.Bytes()
	l, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil },
		tarball.WithMediaType(types.OCILayer))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// img builds an OCI image: base's layers plus layers, with cfg applied.
func img(t *testing.T, base v1.Image, cfg func(*v1.ConfigFile), layers ...v1.Layer) v1.Image {
	t.Helper()
	if base == nil {
		base = mutate.ConfigMediaType(mutate.MediaType(empty.Image, types.OCIManifestSchema1), types.OCIConfigJSON)
	}
	var adds []mutate.Addendum
	for i, l := range layers {
		adds = append(adds, mutate.Addendum{Layer: l, History: v1.History{CreatedBy: "layer " + string(rune('a'+i))}})
	}
	out, err := mutate.Append(base, adds...)
	if err != nil {
		t.Fatal(err)
	}
	cf, err := out.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture = "linux", "amd64"
	if cfg != nil {
		cfg(cf)
	}
	if out, err = mutate.ConfigFile(out, cf); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestImage(t *testing.T) {
	osRel := f{"etc/os-release", "ID=wolfi\nVERSION_ID=20230201\n"}
	oldBase := img(t, nil, func(cf *v1.ConfigFile) {
		cf.Config.User = "65532"
		cf.Config.Env = []string{"PATH=/usr/bin", "SSL_CERT_FILE=/etc/ssl/a.pem"}
		cf.Config.Labels = map[string]string{"base.version": "1", "keep": "x"}
		cf.Created = v1.Time{Time: time.Unix(1700000000, 0).UTC()}
	}, layer(t, f{"etc/", ""}, osRel, f{"usr/lib/libssl.so.3", "old"}))
	newBase := img(t, nil, func(cf *v1.ConfigFile) {
		cf.Config.User = "0"
		cf.Config.Cmd = []string{"/bin/sh"}
		cf.Config.Env = []string{"PATH=/usr/local/bin:/usr/bin", "SSL_CERT_FILE=/etc/ssl/a.pem", "NEW=1"}
		cf.Config.Labels = map[string]string{"base.version": "2", "keep": "x"}
		cf.Created = v1.Time{Time: time.Unix(1800000000, 0).UTC()}
	}, layer(t, f{"etc/", ""}, osRel), layer(t, f{"usr/lib/libssl.so.3", "new"}))
	app := img(t, oldBase, func(cf *v1.ConfigFile) {
		cf.Config.Env = []string{"PATH=/usr/bin", "SSL_CERT_FILE=/etc/ssl/a.pem", "PORT=8080"}
		cf.Config.Entrypoint = []string{"/app/hello"}
		cf.Config.User = "65532" // the same as the old base's: set or inherited?
		cf.Created = v1.Time{Time: time.Unix(1750000000, 0).UTC()}
	}, layer(t, f{"app/", ""}, f{"app/hello", "binary"}))

	r, err := Image(app, oldBase, newBase, "registry.example/base:latest")
	if err != nil {
		t.Fatal(err)
	}
	if err := validate.Image(r.Image); err != nil {
		t.Fatalf("rebased image is invalid: %v", err)
	}
	m, _ := r.Image.Manifest()
	nm, _ := newBase.Manifest()
	am, _ := app.Manifest()
	if len(m.Layers) != 3 || m.Layers[0].Digest != nm.Layers[0].Digest || m.Layers[1].Digest != nm.Layers[1].Digest || m.Layers[2].Digest != am.Layers[1].Digest {
		t.Fatalf("layers = %v", m.Layers)
	}
	nd, _ := newBase.Digest()
	if m.Annotations[AnnotationBaseDigest] != nd.String() || m.Annotations[AnnotationBaseName] != "registry.example/base:latest" {
		t.Errorf("annotations = %v", m.Annotations)
	}
	cf, _ := r.Image.ConfigFile()
	wantEnv := []string{"PATH=/usr/local/bin:/usr/bin", "SSL_CERT_FILE=/etc/ssl/a.pem", "PORT=8080", "NEW=1"}
	if !slices.Equal(cf.Config.Env, wantEnv) {
		t.Errorf("env = %q, want %q", cf.Config.Env, wantEnv)
	}
	if cf.Config.Labels["base.version"] != "2" || cf.Config.Labels["keep"] != "x" {
		t.Errorf("labels = %v", cf.Config.Labels)
	}
	if !slices.Equal(cf.Config.Entrypoint, []string{"/app/hello"}) || cf.Config.User != "65532" || cf.Config.Cmd != nil {
		t.Errorf("how the app runs changed: entrypoint %v, user %q, cmd %v", cf.Config.Entrypoint, cf.Config.User, cf.Config.Cmd)
	}
	if len(r.Kept) != 2 || !strings.Contains(r.Kept[0], `User stays "65532" (the new base sets "0")`) {
		t.Errorf("kept = %q", r.Kept)
	}
	if !cf.Created.Equal(time.Unix(1800000000, 0)) {
		t.Errorf("created = %v, want the new base's", cf.Created)
	}
	acf, _ := app.ConfigFile()
	if len(cf.History) != 3 || cf.History[1].CreatedBy != "layer b" || cf.History[2] != acf.History[1] {
		t.Errorf("history = %+v", cf.History)
	}
	if len(r.Config) != 3 {
		t.Errorf("config changes = %q", r.Config)
	}

	again, err := Image(app, oldBase, newBase, "registry.example/base:latest")
	if err != nil {
		t.Fatal(err)
	}
	d1, _ := r.Image.Digest()
	d2, _ := again.Image.Digest()
	if d1 != d2 {
		t.Errorf("rebase is not deterministic: %s vs %s", d1, d2)
	}

	other := img(t, nil, nil, layer(t, f{"x", "y"}))
	if _, err := Image(app, other, newBase, "b"); err == nil || !strings.Contains(err.Error(), "not built on this base") {
		t.Errorf("rebasing from the wrong base: err = %v", err)
	}

	rep, err := Analyze(Layers{OldBase: layers(t, oldBase), NewBase: layers(t, newBase), App: layers(t, app)[1:], Config: cf.Config})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() {
		t.Errorf("clean app reported problems: %+v", rep)
	}
}

func layers(t *testing.T, i v1.Image) []v1.Layer {
	t.Helper()
	ls, err := i.Layers()
	if err != nil {
		t.Fatal(err)
	}
	return ls
}

func TestAnalyzeViolations(t *testing.T) {
	old := []v1.Layer{layer(t,
		f{"etc/", ""}, f{"etc/passwd", "root"}, f{"etc/hosts", "h"},
		f{"usr/", ""}, f{"usr/lib/", ""}, f{"lib -> usr/lib", ""},
		f{"var/lib/dpkg/status", "Package: base"},
	)}
	nw := []v1.Layer{old[0], layer(t, f{"usr/bin/", ""}, f{"usr/bin/tool", "new"})}
	app := []v1.Layer{layer(t,
		f{"etc/", ""},              // directory over directory: fine
		f{"etc/passwd", "app"},     // replaces a base file
		f{"etc/.wh.hosts", ""},     // deletes a base file
		f{"usr/bin/tool", "mine"},  // hides the new base's file
		f{"lib/libmine.so.1", "x"}, // writes through a base symlink
		f{"var/lib/dpkg/status", "Package: base\n\nPackage: curl"},
		f{"app/ok", "fine"},
	)}
	rep, err := Analyze(Layers{OldBase: old, NewBase: nw, App: app})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(rep.Violations, "\n")
	for _, want := range []string{
		"install OS packages (package database changes): /var/lib/dpkg/status",
		"replace files of the old base: /etc/passwd, /var/lib/dpkg/status",
		"hide files of the new base: /usr/bin/tool",
		"delete files of the old base: /etc/hosts",
		"write through base symlinks: /lib/libmine.so.1 (/lib is a symlink in the old base)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "/app/ok") || strings.Contains(got, "/etc,") {
		t.Errorf("flagged an allowed path:\n%s", got)
	}
}

func TestAnalyzeBreaks(t *testing.T) {
	deb := func(v string) f { return f{"usr/lib/os-release", "ID=debian\nVERSION_ID=\"" + v + "\"\n"} }
	common := []f{
		{"etc/", ""}, {"etc/os-release -> ../usr/lib/os-release", ""},
		{"bin -> usr/bin", ""}, {"usr/bin/sh", "sh"},
		{"lib64/ld-linux-x86-64.so.2", "ld"},
	}
	old := []v1.Layer{layer(t, append(common, deb("12"), f{"usr/lib/x86_64-linux-gnu/libssl.so.3", "ssl"})...)}
	nw := []v1.Layer{layer(t, append(slices.Clone(common[:2]), deb("13"), f{"usr/lib/x86_64-linux-gnu/libssl.so.4", "ssl"})...)}
	prog := elfFile(t, "/lib64/ld-linux-x86-64.so.2", "libssl.so.3", "libmine.so.1")
	app := []v1.Layer{layer(t, f{"app/server", string(prog)}, f{"app/lib/libmine.so.1", "mine"})}

	rep, err := Analyze(Layers{OldBase: old, NewBase: nw, App: app, Config: v1.Config{Entrypoint: []string{"/bin/sh", "-c"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Violations) > 0 {
		t.Errorf("violations: %q", rep.Violations)
	}
	got := strings.Join(rep.Breaks, "\n")
	for _, want := range []string{
		"distribution changed: debian 12 → debian 13",
		"/app/server needs /lib64/ld-linux-x86-64.so.2",
		"/app/server needs libssl.so.3",
		"entrypoint /bin/sh is missing from the new base",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "libmine") {
		t.Errorf("flagged a library the app ships itself:\n%s", got)
	}
}

// elfFile writes a minimal 64-bit ELF with an interpreter and DT_NEEDED
// entries, enough for debug/elf.
func elfFile(t *testing.T, interp string, needed ...string) []byte {
	t.Helper()
	le := binary.LittleEndian
	const ehsize, phsize, shsize = 64, 56, 64
	interpB := append([]byte(interp), 0)
	dynstr := []byte{0}
	var dyn []byte
	for _, n := range needed {
		dyn = le.AppendUint64(dyn, uint64(elf.DT_NEEDED))
		dyn = le.AppendUint64(dyn, uint64(len(dynstr)))
		dynstr = append(append(dynstr, n...), 0)
	}
	dyn = append(dyn, make([]byte, 16)...) // DT_NULL
	shstr := []byte("\x00.interp\x00.dynstr\x00.dynamic\x00.shstrtab\x00")

	offInterp := uint64(ehsize + phsize)
	offDynstr := offInterp + uint64(len(interpB))
	offDyn := offDynstr + uint64(len(dynstr))
	offShstr := offDyn + uint64(len(dyn))
	offSh := offShstr + uint64(len(shstr))

	var b []byte
	b = append(b, 0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT))
	b = append(b, make([]byte, 9)...)
	b = le.AppendUint16(b, uint16(elf.ET_EXEC))
	b = le.AppendUint16(b, uint16(elf.EM_X86_64))
	b = le.AppendUint32(b, uint32(elf.EV_CURRENT))
	b = le.AppendUint64(b, 0)      // entry
	b = le.AppendUint64(b, ehsize) // phoff
	b = le.AppendUint64(b, offSh)  // shoff
	b = le.AppendUint32(b, 0)      // flags
	b = le.AppendUint16(b, ehsize) // ehsize
	b = le.AppendUint16(b, phsize) // phentsize
	b = le.AppendUint16(b, 1)      // phnum
	b = le.AppendUint16(b, shsize) // shentsize
	b = le.AppendUint16(b, 5)      // shnum
	b = le.AppendUint16(b, 4)      // shstrndx
	b = le.AppendUint32(b, uint32(elf.PT_INTERP))
	b = le.AppendUint32(b, uint32(elf.PF_R))
	for _, v := range []uint64{offInterp, 0, 0, uint64(len(interpB)), uint64(len(interpB)), 1} {
		b = le.AppendUint64(b, v)
	}
	b = append(append(append(append(b, interpB...), dynstr...), dyn...), shstr...)
	sh := func(name uint32, typ elf.SectionType, off, size uint64, link uint32, entsize uint64) {
		b = le.AppendUint32(b, name)
		b = le.AppendUint32(b, uint32(typ))
		for _, v := range []uint64{0, 0, off, size} { // flags, addr, offset, size
			b = le.AppendUint64(b, v)
		}
		b = le.AppendUint32(b, link)
		b = le.AppendUint32(b, 0)
		b = le.AppendUint64(b, 1)
		b = le.AppendUint64(b, entsize)
	}
	sh(0, elf.SHT_NULL, 0, 0, 0, 0)
	sh(1, elf.SHT_PROGBITS, offInterp, uint64(len(interpB)), 0, 0)
	sh(9, elf.SHT_STRTAB, offDynstr, uint64(len(dynstr)), 0, 0)
	sh(17, elf.SHT_DYNAMIC, offDyn, uint64(len(dyn)), 2, 16)
	sh(26, elf.SHT_STRTAB, offShstr, uint64(len(shstr)), 0, 0)

	ef, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if libs, _ := ef.ImportedLibraries(); !slices.Equal(libs, needed) {
		t.Fatalf("test ELF imports %v", libs)
	}
	return b
}

func TestIndex(t *testing.T) {
	a := img(t, nil, nil, layer(t, f{"a", "1"}))
	b := img(t, nil, nil, layer(t, f{"b", "2"}))
	att := img(t, nil, nil, layer(t, f{"att", "3"}))
	idx := mutate.IndexMediaType(mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: a, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}},
		mutate.IndexAddendum{Add: b, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "arm64"}}},
		mutate.IndexAddendum{Add: att, Descriptor: v1.Descriptor{
			Platform:    &v1.Platform{OS: "unknown", Architecture: "unknown"},
			Annotations: map[string]string{"vnd.docker.reference.type": "attestation-manifest"},
		}},
	), types.OCIImageIndex)
	ad, _ := a.Digest()
	bd, _ := b.Digest()
	a2 := img(t, nil, nil, layer(t, f{"a", "new"}))
	b2 := img(t, nil, nil, layer(t, f{"b", "new"}))
	out, err := Index(idx, map[v1.Hash]v1.Image{ad: a2, bd: b2}, "base")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := out.RawManifest()
	if d, _ := out.Digest(); d.String() != digestOf(raw) {
		t.Errorf("index digest %s does not match its manifest", d)
	}
	im, _ := out.IndexManifest()
	a2d, _ := a2.Digest()
	if len(im.Manifests) != 2 || im.Manifests[0].Digest != a2d || im.Manifests[1].Platform.Architecture != "arm64" {
		t.Errorf("manifests = %+v", im.Manifests)
	}
	if _, err := Index(idx, map[v1.Hash]v1.Image{ad: a2}, "base"); err == nil {
		t.Error("expected an error when a platform was not rebased")
	}
}

func digestOf(b []byte) string {
	h, _, _ := v1.SHA256(bytes.NewReader(b))
	return h.String()
}

func TestMergeEnv(t *testing.T) {
	j := func(v ...string) json.RawMessage { b, _ := json.Marshal(v); return b }
	got, changes, err := mergeEnv(j("A=1", "B=mine", "C=3"), j("A=1", "B=base", "C=3", "D=4"), j("A=2", "B=base2", "D=4", "E=5"))
	if err != nil {
		t.Fatal(err)
	}
	var env []string
	_ = json.Unmarshal(got, &env)
	// A followed the base; B is the app's own; C was removed by the base;
	// E is new in the base; D was dropped by the app's build.
	if want := []string{"A=2", "B=mine", "E=5"}; !slices.Equal(env, want) {
		t.Errorf("env = %q, want %q (changes %q)", env, want, changes)
	}
	if got, _, _ := mergeEnv(j("A=1"), j("A=1"), j("A=1")); got != nil {
		t.Errorf("unchanged env was rewritten: %s", got)
	}
}
