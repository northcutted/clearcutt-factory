package smoke

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/random"

	"github.com/northcutted/clearcutt-factory/internal/manifest"
)

type fake struct {
	calls   []string
	respond func(args []string) (string, error)
}

func (f *fake) exec(_ context.Context, args ...string) ([]byte, []byte, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	if f.respond != nil {
		out, err := f.respond(args)
		return []byte(out), nil, err
	}
	return nil, nil, nil
}

func (f *fake) called(prefix string) string {
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return c
		}
	}
	return ""
}

func TestCommand(t *testing.T) {
	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	f := &fake{}
	r := &Runner{WorkDir: t.TempDir(), Exec: f.exec}
	test := &manifest.Test{Command: []string{"/usr/local/bin/kubectl", "version", "--client"}}
	if err := r.Run(context.Background(), img, "linux/arm64", "Platform Tools", test); err != nil {
		t.Fatal(err)
	}
	run := f.called("run ")
	if !strings.Contains(run, "--platform linux/arm64 --network none --entrypoint /usr/local/bin/kubectl localhost/clearcutt-factory-smoke/platform-tools:linux-arm64 version --client") {
		t.Errorf("run = %q", run)
	}
	if f.called("load -q -i ") == "" || f.called("rmi -f localhost/clearcutt-factory-smoke/platform-tools:linux-arm64") == "" || f.called("rm -f clearcutt-factory-smoke-") == "" {
		t.Errorf("load/cleanup missing: %q", f.calls)
	}

	f.respond = func(args []string) (string, error) {
		if args[0] == "run" {
			return "", errors.New("exit status 1")
		}
		return "", nil
	}
	if err := r.Run(context.Background(), img, "linux/arm64", "x", test); err == nil {
		t.Error("a failing command passed")
	}
}

// TestNetwork: a command test's container has no network unless the test
// asks for one; an HTTP test's has the default, for its published port.
func TestNetwork(t *testing.T) {
	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		test *manifest.Test
		none bool
	}{
		{"command", &manifest.Test{Command: []string{"/bin/true"}}, true},
		{"command with network", &manifest.Test{Command: []string{"/bin/true"}, Network: true}, false},
	} {
		f := &fake{}
		r := &Runner{WorkDir: t.TempDir(), Exec: f.exec}
		if err := r.Run(context.Background(), img, "linux/amd64", "x", c.test); err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(f.called("run "), " --network none "); got != c.none {
			t.Errorf("%s: run = %q", c.name, f.called("run "))
		}
	}
}

func TestHTTP(t *testing.T) {
	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	status := http.StatusServiceUnavailable
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
		status = http.StatusOK // ready on the second request
	}))
	defer srv.Close()
	port := srv.URL[strings.LastIndex(srv.URL, ":"):]

	running := "true"
	f := &fake{respond: func(args []string) (string, error) {
		switch args[0] {
		case "port":
			return "127.0.0.1" + port + "\n", nil
		case "inspect":
			return running, nil
		}
		return "", nil
	}}
	r := &Runner{WorkDir: t.TempDir(), Exec: f.exec, Poll: time.Millisecond}
	test := &manifest.Test{HTTP: &manifest.HTTPTest{Port: 8080, Path: "/healthz"}, Timeout: "5s"}
	if err := r.Run(context.Background(), img, "linux/amd64", "hello", test); err != nil {
		t.Fatal(err)
	}
	if run := f.called("run "); !strings.Contains(run, "-d -p 127.0.0.1::8080 localhost/clearcutt-factory-smoke/hello:linux-amd64") || strings.Contains(run, "--network") {
		t.Errorf("run = %q", run)
	}

	// A container that exits fails at once, with its logs.
	status, running = http.StatusServiceUnavailable, "false"
	test.HTTP.Path = "/missing"
	err = r.Run(context.Background(), img, "linux/amd64", "hello", test)
	if err == nil || !strings.Contains(err.Error(), "exited before answering /missing") {
		t.Errorf("err = %v", err)
	}
}
