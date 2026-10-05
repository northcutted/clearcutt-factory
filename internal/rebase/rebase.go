// Package rebase moves an application's layers from the base image they were
// built on to a newer build of that base, without rebuilding the application,
// and checks first that the move is safe (see Analyze).
//
// The result depends only on its inputs, so anyone can repeat a rebase from
// the recorded digests and get the same image.
package rebase

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// OCI annotations naming the image an image was built on.
const (
	AnnotationBaseName   = "org.opencontainers.image.base.name"
	AnnotationBaseDigest = "org.opencontainers.image.base.digest"
)

// Rebased is one rebased platform image.
type Rebased struct {
	Image v1.Image
	// AppLayers is how many layers came from the application.
	AppLayers int
	// Config lists configuration values that followed the base's change.
	Config []string
	// Kept lists how the new base would run differently (user, entrypoint,
	// …) where the image keeps its own settings.
	Kept []string
}

// Image puts app's layers above oldBase onto newBase, which is named
// baseName. app's lowest layers must be exactly oldBase's layers.
//
// Environment variables and labels the app inherited unchanged from the old
// base follow the new base (a PATH or JAVA_HOME the base changed, say);
// values the app set itself are kept. How the app runs (user, entrypoint,
// command, working directory, ports, volumes) never changes: an app that
// set USER to the old base's user looks the same as one that inherited it,
// and following the new base there could run it as root. The created time
// is the later of the app's and the new base's.
func Image(app, oldBase, newBase v1.Image, baseName string) (*Rebased, error) {
	am, err := app.Manifest()
	if err != nil {
		return nil, err
	}
	om, err := oldBase.Manifest()
	if err != nil {
		return nil, err
	}
	nm, err := newBase.Manifest()
	if err != nil {
		return nil, err
	}
	if err := BasedOn(am, om); err != nil {
		return nil, err
	}
	acf, err := app.ConfigFile()
	if err != nil {
		return nil, err
	}
	ocf, err := oldBase.ConfigFile()
	if err != nil {
		return nil, err
	}
	ncf, err := newBase.ConfigFile()
	if err != nil {
		return nil, err
	}
	if !samePlatform(platformOf(acf), platformOf(ncf)) {
		return nil, fmt.Errorf("new base is %s, but the image is %s", platformOf(ncf), platformOf(acf))
	}
	for _, c := range []struct {
		name   string
		m      *v1.Manifest
		cf     *v1.ConfigFile
		layers int
	}{{"image", am, acf, len(am.Layers)}, {"old base", om, ocf, len(om.Layers)}, {"new base", nm, ncf, len(nm.Layers)}} {
		if len(c.cf.RootFS.DiffIDs) != c.layers {
			return nil, fmt.Errorf("%s config lists %d layers but its manifest has %d", c.name, len(c.cf.RootFS.DiffIDs), c.layers)
		}
	}
	top := am.Layers[len(om.Layers):]

	raw, err := rawConfig(app)
	if err != nil {
		return nil, err
	}
	newRaw, err := rawConfig(newBase)
	if err != nil {
		return nil, err
	}
	oldRaw, err := rawConfig(oldBase)
	if err != nil {
		return nil, err
	}

	diffIDs := append(slices.Clone(ncf.RootFS.DiffIDs), acf.RootFS.DiffIDs[len(om.Layers):]...)
	if raw["rootfs"], err = json.Marshal(v1.RootFS{Type: "layers", DiffIDs: diffIDs}); err != nil {
		return nil, err
	}
	hist, err := history(raw["history"], oldRaw["history"], len(om.Layers), newRaw["history"], len(diffIDs))
	if err != nil {
		return nil, err
	}
	if hist == nil {
		delete(raw, "history")
	} else {
		raw["history"] = hist
	}
	if ncf.Created.After(acf.Created.Time) {
		raw["created"] = newRaw["created"]
	}
	changes, kept, err := mergeConfig(raw, oldRaw["config"], newRaw["config"])
	if err != nil {
		return nil, err
	}
	cfgBytes, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}

	m := am.DeepCopy()
	cfgDigest, cfgSize, err := v1.SHA256(bytes.NewReader(cfgBytes))
	if err != nil {
		return nil, err
	}
	m.Config.Digest, m.Config.Size, m.Config.Data = cfgDigest, cfgSize, nil
	m.Layers = nil
	layers := map[v1.Hash]v1.Layer{}
	add := func(img v1.Image, d v1.Descriptor) error {
		l, err := img.LayerByDigest(d.Digest)
		if err != nil {
			return err
		}
		d.MediaType = layerMediaType(m.MediaType, d.MediaType)
		m.Layers = append(m.Layers, d)
		layers[d.Digest] = l
		return nil
	}
	for _, d := range nm.Layers {
		if err := add(newBase, d); err != nil {
			return nil, err
		}
	}
	for _, d := range top {
		if err := add(app, d); err != nil {
			return nil, err
		}
	}
	newDigest, err := newBase.Digest()
	if err != nil {
		return nil, err
	}
	if m.Annotations == nil {
		m.Annotations = map[string]string{}
	}
	m.Annotations[AnnotationBaseName] = baseName
	m.Annotations[AnnotationBaseDigest] = newDigest.String()

	mb, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	img, err := partial.CompressedToImage(&image{
		manifest: mb, mediaType: m.MediaType, config: cfgBytes, configDigest: cfgDigest,
		configMediaType: m.Config.MediaType, layers: layers,
	})
	if err != nil {
		return nil, err
	}
	return &Rebased{Image: img, AppLayers: len(top), Config: changes, Kept: kept}, nil
}

// BasedOn checks that the image's lowest layers are exactly the base's.
func BasedOn(img, base *v1.Manifest) error {
	if len(base.Layers) > len(img.Layers) {
		return fmt.Errorf("image is not built on this base: it has %d layers, the base %d", len(img.Layers), len(base.Layers))
	}
	for i, d := range base.Layers {
		if img.Layers[i].Digest != d.Digest {
			return fmt.Errorf("image is not built on this base: layer %d is %s, the base has %s", i, img.Layers[i].Digest, d.Digest)
		}
	}
	return nil
}

// Index rebuilds app's index with each platform image replaced by its
// rebased image (keyed by the old manifest digest), keeping order, platforms,
// and annotations. Attestation manifests describe the old images, so they
// are dropped.
func Index(app v1.ImageIndex, rebased map[v1.Hash]v1.Image, baseName string) (v1.ImageIndex, error) {
	im, err := app.IndexManifest()
	if err != nil {
		return nil, err
	}
	out := im.DeepCopy()
	out.Manifests = nil
	images := map[v1.Hash]v1.Image{}
	for _, d := range im.Manifests {
		img, ok := rebased[d.Digest]
		if !ok {
			if d.Annotations["vnd.docker.reference.type"] == "attestation-manifest" {
				continue
			}
			return nil, fmt.Errorf("index entry %s (%s) was not rebased", d.Digest, platformString(d.Platform))
		}
		nd, err := partial.Descriptor(img)
		if err != nil {
			return nil, err
		}
		d.Digest, d.Size, d.MediaType = nd.Digest, nd.Size, nd.MediaType
		out.Manifests = append(out.Manifests, d)
		images[d.Digest] = img
	}
	if _, ok := out.Annotations[AnnotationBaseName]; ok {
		out.Annotations[AnnotationBaseName] = baseName
	}
	// An index-level base digest would name one platform; drop it rather
	// than leave it pointing at the old base.
	delete(out.Annotations, AnnotationBaseDigest)
	if len(out.Annotations) == 0 {
		out.Annotations = nil
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return &index{manifest: b, parsed: out, images: images}, nil
}

// Platform reads an image's platform from its config.
func Platform(img v1.Image) (v1.Platform, error) {
	cf, err := img.ConfigFile()
	if err != nil {
		return v1.Platform{}, err
	}
	return platformOf(cf), nil
}

func platformOf(cf *v1.ConfigFile) v1.Platform {
	return v1.Platform{OS: cf.OS, Architecture: cf.Architecture, Variant: cf.Variant, OSVersion: cf.OSVersion}
}

// samePlatform compares os, architecture, and variant; arm64's variant
// defaults to v8.
func samePlatform(a, b v1.Platform) bool {
	norm := func(p v1.Platform) string {
		v := p.Variant
		if p.Architecture == "arm64" && v == "v8" {
			v = ""
		}
		return p.OS + "/" + p.Architecture + "/" + v
	}
	return norm(a) == norm(b)
}

// Select returns the image in idx for platform p.
func Select(idx v1.ImageIndex, p v1.Platform) (v1.Image, error) {
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}
	for _, d := range im.Manifests {
		if d.Platform != nil && d.MediaType.IsImage() && samePlatform(*d.Platform, p) {
			return idx.Image(d.Digest)
		}
	}
	return nil, fmt.Errorf("no %s image", p)
}

func platformString(p *v1.Platform) string {
	if p == nil {
		return "no platform"
	}
	return p.String()
}

// layerMediaType keeps layer media types consistent with the manifest: the
// same gzip bytes are a Docker or an OCI layer depending on the manifest.
func layerMediaType(manifest, layer types.MediaType) types.MediaType {
	switch {
	case manifest == types.OCIManifestSchema1 && layer == types.DockerLayer:
		return types.OCILayer
	case manifest == types.DockerManifestSchema2 && layer == types.OCILayer:
		return types.DockerLayer
	}
	return layer
}

func rawConfig(img v1.Image) (map[string]json.RawMessage, error) {
	b, err := img.RawConfigFile()
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parsing image config: %w", err)
	}
	return m, nil
}

// history joins the new base's history with the app's entries above the old
// base. Entries are kept byte for byte. It returns nil when the histories
// can't be split reliably, since a wrong history is worse than none.
func history(appRaw, oldRaw json.RawMessage, oldLayers int, newRaw json.RawMessage, layers int) (json.RawMessage, error) {
	var app, old, nw []json.RawMessage
	for _, x := range []struct {
		raw json.RawMessage
		out *[]json.RawMessage
	}{{appRaw, &app}, {oldRaw, &old}, {newRaw, &nw}} {
		if len(x.raw) > 0 && string(x.raw) != "null" {
			if err := json.Unmarshal(x.raw, x.out); err != nil {
				return nil, fmt.Errorf("parsing image history: %w", err)
			}
		}
	}
	if len(app) == 0 {
		return nil, nil
	}
	split := -1
	if len(old) <= len(app) {
		split = len(old)
		for i := range old {
			if !bytes.Equal(old[i], app[i]) {
				split = -1
				break
			}
		}
	}
	if split < 0 {
		// Count layers instead: the app's part starts after the entry that
		// adds the old base's last layer.
		n := 0
		for i, h := range app {
			if n == oldLayers {
				split = i
				break
			}
			if !emptyLayer(h) {
				n++
			}
		}
		if n == oldLayers && split < 0 {
			split = len(app)
		}
	}
	if split < 0 {
		return nil, nil
	}
	merged := append(slices.Clone(nw), app[split:]...)
	n := 0
	for _, h := range merged {
		if !emptyLayer(h) {
			n++
		}
	}
	if n != layers {
		return nil, nil
	}
	return json.Marshal(merged)
}

func emptyLayer(h json.RawMessage) bool {
	var e struct {
		EmptyLayer bool `json:"empty_layer"`
	}
	_ = json.Unmarshal(h, &e)
	return e.EmptyLayer
}

// mergeConfig updates raw["config"]: an Env or Labels entry the app
// inherited unchanged from the old base takes the new base's value. It
// returns those changes, and notes where the new base would run differently
// but the image keeps its own settings.
func mergeConfig(raw map[string]json.RawMessage, oldRaw, newRaw json.RawMessage) ([]string, []string, error) {
	app, err := object(raw["config"])
	if err != nil {
		return nil, nil, err
	}
	old, err := object(oldRaw)
	if err != nil {
		return nil, nil, err
	}
	nw, err := object(newRaw)
	if err != nil {
		return nil, nil, err
	}
	var kept []string
	for _, k := range []string{"User", "WorkingDir", "Entrypoint", "Cmd", "StopSignal", "Shell", "ExposedPorts", "Volumes", "Healthcheck"} {
		if !sameJSON(old[k], nw[k]) && !sameJSON(app[k], nw[k]) {
			kept = append(kept, fmt.Sprintf("%s stays %s (the new base sets %s)", k, show(app[k]), show(nw[k])))
		}
	}

	var changes []string
	env, envChanges, err := mergeEnv(app["Env"], old["Env"], nw["Env"])
	if err != nil {
		return nil, nil, err
	}
	if env != nil {
		app["Env"] = env
	}
	changes = append(changes, envChanges...)

	labels, labelChanges, err := mergeLabels(app["Labels"], old["Labels"], nw["Labels"])
	if err != nil {
		return nil, nil, err
	}
	if labels != nil {
		app["Labels"] = labels
	}
	changes = append(changes, labelChanges...)

	if len(changes) == 0 {
		return nil, kept, nil
	}
	b, err := json.Marshal(app)
	if err != nil {
		return nil, nil, err
	}
	raw["config"] = b
	return changes, kept, nil
}

// mergeEnv merges KEY=value lists, keeping the app's order and appending
// variables the new base introduced. It returns nil when nothing changed.
func mergeEnv(appRaw, oldRaw, newRaw json.RawMessage) (json.RawMessage, []string, error) {
	var app, old, nw []string
	for _, x := range []struct {
		raw json.RawMessage
		out *[]string
	}{{appRaw, &app}, {oldRaw, &old}, {newRaw, &nw}} {
		if !absent(x.raw) {
			if err := json.Unmarshal(x.raw, x.out); err != nil {
				return nil, nil, fmt.Errorf("parsing Env: %w", err)
			}
		}
	}
	split := func(list []string) (map[string]string, []string) {
		m := map[string]string{}
		var keys []string
		for _, kv := range list {
			k, v, _ := strings.Cut(kv, "=")
			if _, ok := m[k]; !ok {
				keys = append(keys, k)
			}
			m[k] = v
		}
		return m, keys
	}
	a, aKeys := split(app)
	o, _ := split(old)
	n, nKeys := split(nw)
	var out, changes []string
	for _, k := range aKeys {
		ov, inOld := o[k]
		nv, inNew := n[k]
		switch {
		case !inOld || ov != a[k] || (inNew && nv == ov):
			out = append(out, k+"="+a[k])
		case !inNew:
			changes = append(changes, fmt.Sprintf("Env %s removed (was %q)", k, ov))
		default:
			out = append(out, k+"="+nv)
			changes = append(changes, fmt.Sprintf("Env %s: %q → %q", k, ov, nv))
		}
	}
	for _, k := range nKeys {
		if _, inApp := a[k]; inApp {
			continue
		}
		if _, inOld := o[k]; inOld {
			continue // the app's build dropped it
		}
		out = append(out, k+"="+n[k])
		changes = append(changes, fmt.Sprintf("Env %s added: %q", k, n[k]))
	}
	if len(changes) == 0 {
		return nil, nil, nil
	}
	b, err := json.Marshal(out)
	return b, changes, err
}

// mergeLabels merges label maps per key. It returns nil when nothing changed.
func mergeLabels(appRaw, oldRaw, newRaw json.RawMessage) (json.RawMessage, []string, error) {
	var app, old, nw map[string]string
	for _, x := range []struct {
		raw json.RawMessage
		out *map[string]string
	}{{appRaw, &app}, {oldRaw, &old}, {newRaw, &nw}} {
		if !absent(x.raw) {
			if err := json.Unmarshal(x.raw, x.out); err != nil {
				return nil, nil, fmt.Errorf("parsing Labels: %w", err)
			}
		}
	}
	out := maps.Clone(app)
	if out == nil {
		out = map[string]string{}
	}
	var changes []string
	keys := slices.Sorted(maps.Keys(old))
	for _, k := range keys {
		av, inApp := app[k]
		nv, inNew := nw[k]
		if !inApp || av != old[k] || (inNew && nv == av) {
			continue
		}
		if inNew {
			out[k] = nv
			changes = append(changes, fmt.Sprintf("Label %s: %q → %q", k, av, nv))
		} else {
			delete(out, k)
			changes = append(changes, fmt.Sprintf("Label %s removed", k))
		}
	}
	for _, k := range slices.Sorted(maps.Keys(nw)) {
		_, inApp := app[k]
		_, inOld := old[k]
		if !inApp && !inOld {
			out[k] = nw[k]
			changes = append(changes, fmt.Sprintf("Label %s added: %q", k, nw[k]))
		}
	}
	if len(changes) == 0 {
		return nil, nil, nil
	}
	b, err := json.Marshal(out)
	return b, changes, err
}

func object(raw json.RawMessage) (map[string]json.RawMessage, error) {
	m := map[string]json.RawMessage{}
	if absent(raw) {
		return m, nil
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parsing image config: %w", err)
	}
	return m, nil
}

func absent(raw json.RawMessage) bool {
	return len(raw) == 0 || string(raw) == "null"
}

// sameJSON compares two values semantically (absent equals null).
func sameJSON(a, b json.RawMessage) bool {
	if absent(a) || absent(b) {
		return absent(a) && absent(b)
	}
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return bytes.Equal(a, b)
	}
	xb, _ := json.Marshal(x)
	yb, _ := json.Marshal(y)
	return bytes.Equal(xb, yb)
}

func show(raw json.RawMessage) string {
	if absent(raw) {
		return "(unset)"
	}
	return string(raw)
}

// image is a rebased image: new manifest and config bytes over layers
// borrowed from the new base and the app.
type image struct {
	manifest        []byte
	mediaType       types.MediaType
	config          []byte
	configDigest    v1.Hash
	configMediaType types.MediaType
	layers          map[v1.Hash]v1.Layer
}

func (i *image) RawManifest() ([]byte, error)        { return i.manifest, nil }
func (i *image) RawConfigFile() ([]byte, error)      { return i.config, nil }
func (i *image) MediaType() (types.MediaType, error) { return i.mediaType, nil }
func (i *image) ConfigLayer() (v1.Layer, error) {
	return static.NewLayer(i.config, i.configMediaType), nil
}
func (i *image) LayerByDigest(h v1.Hash) (partial.CompressedLayer, error) {
	if l, ok := i.layers[h]; ok {
		return l, nil
	}
	if h == i.configDigest {
		return i.ConfigLayer()
	}
	return nil, fmt.Errorf("blob %s is not part of this image", h)
}

// index is a rebuilt index over rebased images.
type index struct {
	manifest []byte
	parsed   *v1.IndexManifest
	images   map[v1.Hash]v1.Image
}

func (x *index) MediaType() (types.MediaType, error) { return x.parsed.MediaType, nil }
func (x *index) Digest() (v1.Hash, error) {
	h, _, err := v1.SHA256(bytes.NewReader(x.manifest))
	return h, err
}
func (x *index) Size() (int64, error)                      { return int64(len(x.manifest)), nil }
func (x *index) IndexManifest() (*v1.IndexManifest, error) { return x.parsed.DeepCopy(), nil }
func (x *index) RawManifest() ([]byte, error)              { return x.manifest, nil }
func (x *index) Image(h v1.Hash) (v1.Image, error) {
	if img, ok := x.images[h]; ok {
		return img, nil
	}
	return nil, fmt.Errorf("image %s is not in this index", h)
}
func (x *index) ImageIndex(h v1.Hash) (v1.ImageIndex, error) {
	return nil, fmt.Errorf("index %s is not in this index", h)
}
