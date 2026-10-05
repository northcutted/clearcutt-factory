package native

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/northcutted/declarative-image-factory/internal/container"
	"github.com/northcutted/declarative-image-factory/internal/lock"
)

// dnfScript runs in an RPM-based base. dnf decides what to install and
// downloads it; rpm reports each file's identity and checks its signature
// against the distribution keys shipped in the image.
const dnfScript = `set -eu
command -v dnf >/dev/null 2>&1 || { echo "factory: dnf is not available in the base image (microdnf-only images can't be locked yet)" >&2; exit 3; }
. /etc/os-release
echo "### os"
echo "${ID:-} ${VERSION_ID:-}"
dnf -q -y install --downloadonly --setopt=install_weak_deps=False --setopt=keepcache=True "$@" >&2
files=""
for f in /var/cache/dnf/*/packages/*.rpm /var/cache/libdnf5/*/packages/*.rpm /var/cache/yum/*/*/packages/*.rpm; do
  [ -f "$f" ] && files="$files $f"
done
echo "### rpms"
for f in $files; do
  printf '%s\t' "$(sha256sum "$f" | cut -d' ' -f1)"
  rpm -qp --nosignature --qf '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\t%{LICENSE}\t%|RSAHEADER?{%{RSAHEADER:pgpsig}}:{%|DSAHEADER?{%{DSAHEADER:pgpsig}}:{none}|}|\n' "$f"
done
for k in /etc/pki/rpm-gpg/*; do
  [ -f "$k" ] && rpm --import "$k" 2>/dev/null || true
done
echo "### signatures"
[ -z "$files" ] || rpm -K $files || true
echo "### urls"
nevras=""
for f in $files; do
  nevras="$nevras $(rpm -qp --nosignature --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}' "$f")"
done
[ -z "$nevras" ] || dnf -q repoquery --location $nevras
`

// ResolveDNF resolves packages for one platform in image.
func ResolveDNF(ctx context.Context, run container.RunFunc, image, platform string, packages []string) (*Result, error) {
	out, err := run(ctx, image, platform, dnfScript, packages...)
	if err != nil {
		return nil, err
	}
	return parseDNF(out)
}

func parseDNF(out []byte) (*Result, error) {
	sec := sections(out)
	osLine, err := requireSection(sec, "os")
	if err != nil {
		return nil, err
	}
	osFields := strings.Fields(strings.Join(osLine, " "))
	if len(osFields) == 0 {
		return nil, fmt.Errorf("could not read os-release from the base image")
	}
	res := &Result{Distro: strings.Join(osFields, "-")}
	distroID := osFields[0]

	// Every downloaded file must carry a valid signature from a key the
	// distribution ships.
	for _, line := range sec["signatures"] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.HasSuffix(line, "signatures OK") {
			return nil, fmt.Errorf("signature check failed: %s", line)
		}
	}

	urls := map[string]string{}
	for _, u := range sec["urls"] {
		if u = strings.TrimSpace(u); u != "" {
			urls[path.Base(u)] = u
		}
	}
	repos := map[string]bool{}
	for _, line := range sec["rpms"] {
		f := strings.Split(line, "\t")
		if len(f) < 8 {
			continue
		}
		sum, name, epoch, ver, rel, arch, srpm, license := f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7]
		sig := ""
		if len(f) > 8 {
			sig = f[8]
		}
		file := fmt.Sprintf("%s-%s-%s.%s.rpm", name, ver, rel, arch)
		raw, ok := urls[file]
		if !ok {
			return nil, fmt.Errorf("dnf downloaded %s but repoquery reported no location for it", file)
		}
		u, warn := permanentRPMURL(distroID, raw, file, srpm, arch, signingKey(sig))
		if warn != "" {
			res.Warnings = append(res.Warnings, warn)
		}
		version := ver + "-" + rel
		if epoch != "0" && epoch != "" {
			version = epoch + ":" + version
		}
		origin := strings.TrimSuffix(srpm, ".src.rpm")
		if n, _, ok := splitNVR(origin); ok {
			origin = n
		}
		repo := repoOf(raw)
		repos[repo] = true
		res.Packages = append(res.Packages, lock.Package{
			Name: name, Version: version, Arch: arch, URL: escapePlus(u), Filename: file,
			SHA256: sum, Origin: origin, License: license, Repo: repo,
		})
	}
	for r := range repos {
		res.Repositories = append(res.Repositories, r)
	}
	sort.Strings(res.Repositories)
	sort.Slice(res.Packages, func(i, j int) bool { return res.Packages[i].Name < res.Packages[j].Name })
	return res, nil
}

// permanentRPMURL prefers URLs that outlive repository pruning. Fedora's
// update repos keep only the newest build, but Koji keeps builds, including
// the signed copy (identical to the repository's file) under data/signed/<key>.
func permanentRPMURL(distro, raw, file, srpm, arch, key string) (string, string) {
	if distro == "fedora" && key != "" {
		if n, v, ok := splitNVR(strings.TrimSuffix(srpm, ".src.rpm")); ok {
			ver, rel, _ := strings.Cut(v, "-")
			return fmt.Sprintf("https://kojipkgs.fedoraproject.org/packages/%s/%s/%s/data/signed/%s/%s/%s", n, ver, rel, key, arch, file), ""
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw, ""
	}
	u.Path = path.Clean(u.Path) // Amazon Linux locations contain ../ segments
	warn := ""
	if distro != "amzn" {
		warn = fmt.Sprintf("%s is served from %s, which may drop it when newer builds ship; mirror it", file, u.Host)
	}
	return u.String(), warn
}

// repoOf trims a package location to its repository: the part before
// /Packages/, or before ../ for Amazon Linux's content-addressed blobstore.
func repoOf(raw string) string {
	for _, sep := range []string{"/Packages/", "/../"} {
		if i := strings.Index(raw, sep); i >= 0 {
			return raw[:i]
		}
	}
	return path.Dir(raw)
}

// signingKey extracts Koji's short key ID from rpm's pgpsig rendering,
// e.g. "RSA/SHA256, Mon 01 Jan 2026, Key ID 809a8d7c6d9f90a6" → 6d9f90a6.
func signingKey(pgpsig string) string {
	_, id, ok := strings.Cut(pgpsig, "Key ID ")
	id = strings.ToLower(strings.TrimSpace(id))
	if !ok || len(id) < 8 {
		return ""
	}
	return id[len(id)-8:]
}

// splitNVR splits name-version-release into name and version-release.
func splitNVR(nvr string) (name, vr string, ok bool) {
	i := strings.LastIndex(nvr, "-")
	if i <= 0 {
		return "", "", false
	}
	j := strings.LastIndex(nvr[:i], "-")
	if j <= 0 {
		return "", "", false
	}
	return nvr[:j], nvr[j+1:], true
}
