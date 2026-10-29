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
