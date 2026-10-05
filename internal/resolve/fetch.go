package resolve

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"strings"
)

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (r *Resolver) get(ctx context.Context, url string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, &httpError{url: url, status: resp.StatusCode, text: resp.Status}
	}
	return resp, nil
}

type httpError struct {
	url    string
	status int
	text   string
}

func (e *httpError) Error() string { return fmt.Sprintf("GET %s: %s", e.url, e.text) }

func (r *Resolver) getBytes(ctx context.Context, url string, headers map[string]string) ([]byte, error) {
	resp, err := r.get(ctx, url, headers)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}

func (r *Resolver) getJSON(ctx context.Context, url string, headers map[string]string, v any) error {
	b, err := r.getBytes(ctx, url, headers)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// hashURL downloads url and returns its sha256.
func (r *Resolver) hashURL(ctx context.Context, url string) (string, error) {
	resp, err := r.get(ctx, url, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, resp.Body); err != nil {
		return "", fmt.Errorf("downloading %s: %w", url, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// parseChecksum finds the sha256 for filename in a checksum file. It accepts a
// bare hash, sha256sum output ("<hash>  [*]<name>"), and BSD style
// ("SHA256 (<name>) = <hash>").
func parseChecksum(body []byte, filename string) (string, error) {
	text := strings.TrimSpace(string(body))
	if f := strings.Fields(text); len(f) == 1 && hex64.MatchString(strings.ToLower(f[0])) {
		return strings.ToLower(f[0]), nil
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "SHA256 ("); ok {
			name, hash, ok := strings.Cut(rest, ") = ")
			if ok && path.Base(name) == filename && hex64.MatchString(strings.ToLower(hash)) {
				return strings.ToLower(hash), nil
			}
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		name := strings.TrimPrefix(f[len(f)-1], "*")
		if path.Base(name) == filename && hex64.MatchString(strings.ToLower(f[0])) {
			return strings.ToLower(f[0]), nil
		}
	}
	return "", fmt.Errorf("no sha256 for %s in checksum file", filename)
}

// expand substitutes {{var}} placeholders, failing on unknown ones so typos
// don't silently produce a wrong URL.
func expand(tmpl string, vars map[string]string) (string, error) {
	var b strings.Builder
	for {
		i := strings.Index(tmpl, "{{")
		if i < 0 {
			b.WriteString(tmpl)
			return b.String(), nil
		}
		j := strings.Index(tmpl[i:], "}}")
		if j < 0 {
			return "", fmt.Errorf("unterminated {{ in %q", tmpl)
		}
		key := strings.TrimSpace(tmpl[i+2 : i+j])
		v, ok := vars[key]
		if !ok {
			return "", fmt.Errorf("unknown placeholder {{%s}} in %q", key, tmpl)
		}
		b.WriteString(tmpl[:i])
		b.WriteString(v)
		tmpl = tmpl[i+j+2:]
	}
}
