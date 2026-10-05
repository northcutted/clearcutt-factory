// Package native resolves apt and dnf packages with the distribution's own
// tools, run inside the pinned base image at lock time. Their solvers decide
// what to install; factory records each package file's URL and sha256 so
// builds install exactly that set, offline, from verified files.
package native

import (
	"bufio"
	"bytes"
	"fmt"
	"net/url"
	"strings"

	"github.com/northcutted/declarative-image-factory/internal/lock"
)

// Result is one platform's resolution.
type Result struct {
	Distro       string // os-release ID-VERSION_ID
	Snapshot     string
	Repositories []string
	Packages     []lock.Package
	Warnings     []string
}

// OSRelease parses /etc/os-release.
func OSRelease(b []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		out[k] = strings.Trim(v, `"'`)
	}
	return out
}

// DetectManager picks apt or dnf from os-release, or "" if unknown.
func DetectManager(osr map[string]string) string {
	ids := append([]string{osr["ID"]}, strings.Fields(osr["ID_LIKE"])...)
	for _, id := range ids {
		switch id {
		case "debian", "ubuntu":
			return lock.ManagerAPT
		case "fedora", "rhel", "centos", "amzn", "rocky", "almalinux", "ol":
			return lock.ManagerDNF
		case "alpine", "wolfi", "chainguard":
			return lock.ManagerAPK
		}
	}
	return ""
}

// sections splits script output on "### name" marker lines.
func sections(out []byte) map[string][]string {
	s := map[string][]string{}
	cur := ""
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		line := sc.Text()
		if name, ok := strings.CutPrefix(line, "### "); ok {
			cur = name
			if _, seen := s[cur]; !seen {
				s[cur] = nil
			}
			continue
		}
		if cur != "" {
			s[cur] = append(s[cur], line)
		}
	}
	return s
}

// escapePlus percent-encodes '+' in a URL's last path segment (the file
// name). S3-style CDNs (Amazon Linux) read a literal '+' as a space and serve
// an error page; earlier segments are left alone (Launchpad's /+files/).
func escapePlus(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	p := u.EscapedPath()
	i := strings.LastIndex(p, "/") + 1
	u.RawPath = p[:i] + strings.ReplaceAll(p[i:], "+", "%2B")
	return u.String()
}

func requireSection(s map[string][]string, name string) ([]string, error) {
	lines, ok := s[name]
	if !ok {
		return nil, fmt.Errorf("resolver output is missing the %q section", name)
	}
	return lines, nil
}
