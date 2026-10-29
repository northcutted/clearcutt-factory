package factory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// repoFile reads a file of this repository, from the package directory.
func repoFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(path)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type workflowStep struct {
	Name string            `yaml:"name"`
	If   string            `yaml:"if"`
	Uses string            `yaml:"uses"`
	With map[string]string `yaml:"with"`
}

type reusableWorkflow struct {
	On struct {
		WorkflowCall struct {
			Inputs  map[string]any `yaml:"inputs"`
			Secrets map[string]any `yaml:"secrets"`
		} `yaml:"workflow_call"`
	} `yaml:"on"`
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]struct {
		Permissions map[string]string `yaml:"permissions"`
		Steps       []workflowStep    `yaml:"steps"`
		Uses        string            `yaml:"uses"`
		With        map[string]any    `yaml:"with"`
		Secrets     any               `yaml:"secrets"`
	} `yaml:"jobs"`
}

func readWorkflow(t *testing.T, path string) reusableWorkflow {
	t.Helper()
	var wf reusableWorkflow
	if err := yaml.Unmarshal(repoFile(t, path), &wf); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return wf
}

// Every job of the reusable workflows that logs in to the registry with a
// username and password can log in by OIDC federation instead
// (registry-login/action.yml), under the same condition, with every input
// the action takes, each declared by the workflow; and the password login
// steps aside when it does.
func TestRegistryLoginByOIDCEverywhere(t *testing.T) {
	var action struct {
		Inputs map[string]any `yaml:"inputs"`
	}
	if err := yaml.Unmarshal(repoFile(t, "registry-login/action.yml"), &action); err != nil {
		t.Fatal(err)
	}
	logins := 0
	for _, name := range []string{"images", "fleet", "reattest"} {
		path := ".github/workflows/" + name + ".yml"
		wf := readWorkflow(t, path)
		for jobName, job := range wf.Jobs {
			for i, step := range job.Steps {
				if !strings.HasPrefix(step.Uses, "docker/login-action@") || step.With["registry"] != "${{ env.REGISTRY }}" {
					continue
				}
				logins++
				where := path + " " + jobName
				cond, ok := strings.CutSuffix(step.If, "env.OIDC_LOGIN != 'true'")
				if !ok {
					t.Errorf("%s: the password login runs on %q, also when logging in by OIDC", where, step.If)
					continue
				}
				if i+1 >= len(job.Steps) || job.Steps[i+1].Uses != "./.clearcutt-factory/registry-login" {
					t.Errorf("%s: no OIDC login after the password login", where)
					continue
				}
				oidc := job.Steps[i+1]
				if oidc.If != cond+"env.OIDC_LOGIN == 'true'" {
					t.Errorf("%s: the OIDC login runs on %q, not as the password login does (%q)", where, oidc.If, step.If)
				}
				for in := range action.Inputs {
					want := "${{ inputs." + in + " }}"
					if in == "registry" {
						want = "${{ env.REGISTRY }}"
					} else if _, ok := wf.On.WorkflowCall.Inputs[in]; !ok {
						t.Errorf("%s doesn't declare the input %s", path, in)
					}
					if oidc.With[in] != want {
						t.Errorf("%s: the OIDC login passes %s: %q, want %q", where, in, oidc.With[in], want)
					}
				}
				if len(oidc.With) != len(action.Inputs) {
					t.Errorf("%s: the OIDC login passes %v; the action takes %v", where, oidc.With, action.Inputs)
				}
				if job.Permissions["id-token"] != "write" {
					t.Errorf("%s: logging in by OIDC needs id-token: write", where)
				}
			}
		}
	}
	if logins != 4 {
		t.Errorf("%d registry logins, want 4 (images: build and reproduce; fleet; reattest)", logins)
	}
}

// checkCalls checks the jobs of a workflow that call reusable workflows,
// factory's (read from this repository) or the caller's own (./…, read by
// local): each passes only the inputs and secrets the called workflow
// declares (GitHub rejects others), secrets by name (secrets: inherit
// doesn't reach workflows in another organization), and grants every
// permission the called workflow's jobs ask for (GitHub fails a run whose
// called workflow asks for more than its caller granted). It returns the
// refs factory's workflows are called at.
func checkCalls(t *testing.T, where string, b []byte, local func(path string) []byte) (refs []string) {
	t.Helper()
	var wf reusableWorkflow
	if err := yaml.Unmarshal(b, &wf); err != nil {
		t.Fatalf("%s: %v", where, err)
	}
	level := map[string]int{"": 0, "none": 0, "read": 1, "write": 2}
	for name, job := range wf.Jobs {
		var called []byte
		var path string
		switch {
		case strings.HasPrefix(job.Uses, "northcutted/clearcutt-factory/"):
			rest := strings.TrimPrefix(job.Uses, "northcutted/clearcutt-factory/")
			var ref string
			path, ref, _ = strings.Cut(rest, "@")
			refs = append(refs, ref)
			called = repoFile(t, path)
		case strings.HasPrefix(job.Uses, "./"):
			path = strings.TrimPrefix(job.Uses, "./")
			if local == nil {
				t.Errorf("%s: job %s calls %s, a workflow of the caller's", where, name, job.Uses)
				continue
			}
			called = local(path)
		default:
			continue
		}
		var reusable reusableWorkflow
		if err := yaml.Unmarshal(called, &reusable); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for k := range job.With {
			if _, ok := reusable.On.WorkflowCall.Inputs[k]; !ok {
				t.Errorf("%s: job %s passes input %s, which %s doesn't declare", where, name, k, path)
			}
		}
		secrets, ok := job.Secrets.(map[string]any)
		if job.Secrets != nil && !ok {
			t.Errorf("%s: job %s passes secrets %v; name them", where, name, job.Secrets)
		}
		for k := range secrets {
			if _, ok := reusable.On.WorkflowCall.Secrets[k]; !ok {
				t.Errorf("%s: job %s passes secret %s, which %s doesn't declare", where, name, k, path)
			}
		}
		var jobPerms struct {
			Jobs map[string]struct {
				Permissions map[string]string `yaml:"permissions"`
			} `yaml:"jobs"`
		}
		_ = yaml.Unmarshal(b, &jobPerms)
		granted := jobPerms.Jobs[name].Permissions
		asks := []map[string]string{reusable.Permissions}
		for _, j := range reusable.Jobs {
			asks = append(asks, j.Permissions)
		}
		for _, ask := range asks {
			for scope, want := range ask {
				if got := granted[scope]; level[got] < level[want] {
					t.Errorf("%s: job %s grants %s %q, but %s asks for %q", where, name, scope, got, path, want)
				}
			}
		}
	}
	return refs
}

// app.yml calls factory's reusable workflows as they take it, all at one
// ref: main between releases, else the release its factory-version
// default names (scripts/release.sh moves both), so a caller pinning
// app.yml gets the workflows of the same release.
func TestAppWorkflowCalls(t *testing.T) {
	b := repoFile(t, ".github/workflows/app.yml")
	refs := checkCalls(t, "app.yml", b, nil)
	if len(refs) != 6 {
		t.Errorf("app.yml calls factory's workflows %d times, want 6 (images, reproduce, fleet, update-locks, reattest, estate-changed)", len(refs))
	}
	var wf struct {
		On struct {
			WorkflowCall struct {
				Inputs map[string]struct {
					Default any `yaml:"default"`
				} `yaml:"inputs"`
				Secrets map[string]any `yaml:"secrets"`
			} `yaml:"workflow_call"`
		} `yaml:"on"`
		Jobs map[string]struct {
			Secrets map[string]string `yaml:"secrets"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(b, &wf); err != nil {
		t.Fatal(err)
	}
	release, _ := wf.On.WorkflowCall.Inputs["factory-version"].Default.(string)
	for _, ref := range refs {
		if ref != refs[0] || (ref != "main" && ref != release) {
			t.Errorf("app.yml calls factory's workflows at %v; want them all at main or %s (its factory-version)", refs, release)
			break
		}
	}
	// What it passes on, it takes: every secret it hands down is one of its own.
	for name, job := range wf.Jobs {
		for k, v := range job.Secrets {
			if v != "${{ secrets."+k+" }}" {
				t.Errorf("job %s passes secret %s as %s", name, k, v)
			}
			if _, ok := wf.On.WorkflowCall.Secrets[k]; !ok {
				t.Errorf("job %s passes secret %s, which app.yml doesn't take", name, k)
			}
		}
	}
	// Each of the OIDC login inputs reaches every workflow that logs in.
	var action struct {
		Inputs map[string]any `yaml:"inputs"`
	}
	if err := yaml.Unmarshal(repoFile(t, "registry-login/action.yml"), &action); err != nil {
		t.Fatal(err)
	}
	var calls reusableWorkflow
	_ = yaml.Unmarshal(b, &calls)
	for _, job := range []string{"images", "reproduce", "fleet", "reattest"} {
		for in := range action.Inputs {
			if in == "registry" {
				continue
			}
			if calls.Jobs[job].With[in] != "${{ inputs."+in+" }}" {
				t.Errorf("job %s doesn't pass %s on", job, in)
			}
		}
	}
}
