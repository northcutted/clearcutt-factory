package native

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/northcutted/clearcutt-factory/internal/container"
	"github.com/northcutted/clearcutt-factory/internal/lock"
)

// aptScript runs in a Debian or Ubuntu base. Debian sources are pointed at
// snapshot.debian.org so the resolution is repeatable and every URL is
// permanent; apt still verifies the signed indexes. $1 is the snapshot
// timestamp, then come the options aptArgs writes, then the requested
// packages.
//
// To keep packages at their locked versions (lock --update-package), each
// --pin=NAME=VERSION becomes an apt preference that apt takes wherever it
// needs NAME: a dependency that needs another version is an unmet one
// rather than a quiet upgrade, and a pinned package nothing needs isn't
// installed. Each --keep-snapshot=TS adds the Debian snapshot a pinned
// version came from, since a newer snapshot lists only the archive's
// versions of its day.
const aptScript = `set -eu
export DEBIAN_FRONTEND=noninteractive
TS="$1"; shift
command -v apt-get >/dev/null 2>&1 || { echo "clearcutt-factory: apt-get is not available in the base image" >&2; exit 3; }
KEEP_TS=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --keep-snapshot=*) KEEP_TS="$KEEP_TS ${1#*=}" ;;
    --pin=*)
      pin="${1#--pin=}"
      printf 'Package: %s\nPin: version %s\nPin-Priority: 1001\n\n' "${pin%%=*}" "${pin#*=}" >> /etc/apt/preferences.d/clearcutt-factory
      ;;
    *) break ;;
  esac
  shift
done
. /etc/os-release
echo "### os"
echo "${ID:-} ${VERSION_ID:-}"
snapshot() {
  ts="$1"; shift
  sed -E \
    -e "s#https?://(deb|security|ftp)\.debian\.org/debian-security/?#http://snapshot.debian.org/archive/debian-security/$ts/#g" \
    -e "s#https?://(deb|ftp)\.debian\.org/debian/?#http://snapshot.debian.org/archive/debian/$ts/#g" \
    "$@"
}
if [ "${ID:-}" = debian ]; then
  n=0
  for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
    [ -f "$f" ] || continue
    for ts in $KEEP_TS; do
      [ "$ts" != "$TS" ] || continue
      n=$((n + 1))
      snapshot "$ts" "$f" > "/etc/apt/sources.list.d/clearcutt-factory-kept-$n.${f##*.}"
    done
    snapshot "$TS" -i "$f"
  done
fi
apt-get -qq -o Acquire::Check-Valid-Until=false update >&2
echo "### sources"
apt-get indextargets --format '$(REPO_URI)' | sort -u
echo "### simulate"
# apt lists unmet dependencies on stdout; show them when it fails.
apt-get install -s -y --no-install-recommends "$@" > /tmp/simulate || { cat /tmp/simulate >&2; exit 1; }
cat /tmp/simulate
echo "### uris"
apt-get install --print-uris -qq -y --no-install-recommends "$@"
echo "### records"
pins=$(awk '$1=="Inst" { for (i = 3; i <= NF; i++) if ($i ~ /^\(/) { print $2 "=" substr($i, 2); break } }' /tmp/simulate)
[ -z "$pins" ] || apt-cache show $pins
`

// ResolveAPT resolves packages for one platform in image. keep lists
// packages to keep at their versions wherever apt needs them (from
// lock --update-package); it is empty for a plain resolution.
func ResolveAPT(ctx context.Context, run container.RunFunc, image, platform, snapshot string, packages []string, keep []lock.Package) (*Result, error) {
	out, err := run(ctx, image, platform, aptScript, aptArgs(snapshot, packages, keep)...)
	if err != nil {
		return nil, err
	}
	return parseAPT(out, snapshot)
}

var debianSnapshot = regexp.MustCompile(`^https?://snapshot\.debian\.org/archive/[^/]+/(\d{8}T\d{6}Z)/`)

// aptArgs are aptScript's arguments: the snapshot, a --pin for each kept
// package and a --keep-snapshot for each Debian snapshot they came from,
// then the packages.
func aptArgs(snapshot string, packages []string, keep []lock.Package) []string {
	args := []string{snapshot}
	var snapshots []string
	for _, p := range keep {
		if m := debianSnapshot.FindStringSubmatch(p.URL); m != nil && !slices.Contains(snapshots, m[1]) {
			snapshots = append(snapshots, m[1])
		}
	}
	slices.Sort(snapshots)
	for _, ts := range snapshots {
		args = append(args, "--keep-snapshot="+ts)
	}
	for _, p := range keep {
		args = append(args, "--pin="+p.Name+"="+p.Version)
	}
	return append(args, packages...)
}

type aptInst struct{ version, arch string }

func parseAPT(out []byte, snapshot string) (*Result, error) {
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
	if distroID == "debian" {
		res.Snapshot = snapshot
	}
	for _, s := range sec["sources"] {
		if s = strings.TrimSpace(s); s != "" {
			res.Repositories = append(res.Repositories, s)
		}
	}

	// Inst <name> [<old version>] (<version> <release…> [<arch>])
	insts := map[string]aptInst{}
	var order []string
	for _, line := range sec["simulate"] {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "Inst" {
			continue
		}
		var v string
		for _, x := range f[2:] {
			if strings.HasPrefix(x, "(") {
				v = strings.TrimPrefix(x, "(")
				break
			}
		}
		arch := ""
		if i := strings.LastIndex(line, "["); i >= 0 {
			arch = strings.TrimSuffix(strings.TrimSuffix(line[i+1:], ")"), "]")
		}
		insts[f[1]] = aptInst{v, arch}
		order = append(order, f[1])
	}

	// 'URL' local-filename size hash. The local filename encodes epochs
	// (1%3a…) but pool filenames don't, so key on the URL's basename.
	uris := map[string]string{}
	for _, line := range sec["uris"] {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		raw := strings.Trim(f[0], "'")
		base := path.Base(raw)
		if unesc, err := url.PathUnescape(base); err == nil {
			base = unesc
		}
		uris[base] = raw
	}

	records := map[string]map[string]string{}
	for _, r := range parseStanzas(sec["records"]) {
		records[r["Package"]+"="+r["Version"]] = r
	}

	for _, name := range order {
		in := insts[name]
		bare, _, _ := strings.Cut(name, ":")
		r := records[bare+"="+in.version]
		if r == nil {
			return nil, fmt.Errorf("apt chose %s %s but apt-cache has no record of it", name, in.version)
		}
		file := path.Base(r["Filename"])
		raw, ok := uris[file]
		if !ok {
			return nil, fmt.Errorf("apt chose %s %s but printed no download URL for %s", name, in.version, file)
		}
		if r["SHA256"] == "" {
			return nil, fmt.Errorf("%s %s has no SHA256 in the package index", name, in.version)
		}
		u, warn := permanentDebURL(distroID, raw, file)
		if warn != "" {
			res.Warnings = append(res.Warnings, warn)
		}
		origin, _, _ := strings.Cut(r["Source"], " ")
		res.Packages = append(res.Packages, lock.Package{
			Name: bare, Version: in.version, Arch: r["Architecture"],
			URL: escapePlus(u), Filename: file, SHA256: r["SHA256"], Origin: origin,
			Repo: strings.SplitN(raw, "/pool/", 2)[0],
		})
	}
	sort.Slice(res.Packages, func(i, j int) bool { return res.Packages[i].Name < res.Packages[j].Name })
	return res, nil
}

// permanentDebURL maps a download URL to one that keeps working after the
// archive moves on. Debian snapshot URLs already are; Ubuntu's archive drops
// superseded versions, but Launchpad serves every published file forever.
func permanentDebURL(distro, raw, file string) (string, string) {
	u, err := url.Parse(raw)
	if err != nil {
		return raw, ""
	}
	switch {
	case u.Host == "snapshot.debian.org":
		u.Scheme = "https"
		return u.String(), ""
	case distro == "ubuntu" && (strings.HasSuffix(u.Host, "archive.ubuntu.com") || u.Host == "security.ubuntu.com" || u.Host == "ports.ubuntu.com"):
		return "https://launchpad.net/ubuntu/+archive/primary/+files/" + url.PathEscape(file), ""
	}
	return raw, fmt.Sprintf("%s is served from %s, which may drop it later; mirror it", file, u.Host)
}

// parseStanzas parses deb822 paragraphs (continuation lines are skipped).
func parseStanzas(lines []string) []map[string]string {
	var out []map[string]string
	cur := map[string]string{}
	for _, l := range append(lines, "") {
		if strings.TrimSpace(l) == "" {
			if len(cur) > 0 {
				out = append(out, cur)
				cur = map[string]string{}
			}
			continue
		}
		if l[0] == ' ' || l[0] == '\t' {
			continue
		}
		if k, v, ok := strings.Cut(l, ":"); ok {
			cur[k] = strings.TrimSpace(v)
		}
	}
	return out
}
