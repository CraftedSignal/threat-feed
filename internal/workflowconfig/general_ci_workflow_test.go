package workflowconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func loadWorkflow(t *testing.T, name string) map[string]any {
	t.Helper()

	path := filepath.Join("..", "..", ".github", "workflows", name)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var workflow map[string]any
	if err := yaml.Unmarshal(contents, &workflow); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return workflow
}

func TestSecretScanningUsesBoundedPullRequestHistory(t *testing.T) {
	workflow := loadWorkflow(t, "security.yml")
	jobs := mapping(t, workflow["jobs"], "jobs")
	secretScan := mapping(t, jobs["secrets-scan"], "jobs.secrets-scan")
	steps := sequence(t, secretScan["steps"], "jobs.secrets-scan.steps")

	foundCheckout := false
	foundBaseFetch := false
	for _, raw := range steps {
		step := mapping(t, raw, "jobs.secrets-scan.steps")
		uses, _ := step["uses"].(string)
		if strings.Contains(uses, "actions/checkout") {
			foundCheckout = true
			with := mapping(t, step["with"], "jobs.secrets-scan.checkout.with")
			if with["fetch-depth"] == 0 {
				t.Fatal("secret scan must not clone the repository's full generated history")
			}
			if with["fetch-depth"] == nil {
				t.Fatal("secret scan must use an explicit bounded checkout depth")
			}
		}
		run, _ := step["run"].(string)
		if strings.Contains(run, "git fetch --no-tags --depth=1") && strings.Contains(run, "BASE_SHA") {
			foundBaseFetch = true
		}
	}
	if !foundCheckout || !foundBaseFetch {
		t.Fatalf("secret scan checkout=%v base-fetch=%v, want both", foundCheckout, foundBaseFetch)
	}
}

func TestGeneralCIValidatesPullRequestsWithoutRepeatingOnMerge(t *testing.T) {
	for _, name := range []string{"test.yml", "lint.yml", "codeql.yml", "security.yml"} {
		t.Run(name, func(t *testing.T) {
			workflow := loadWorkflow(t, name)
			triggers := mapping(t, workflow["on"], "on")

			if _, exists := triggers["push"]; exists {
				t.Fatal("on.push duplicates the pull-request checks after merge")
			}
			if _, exists := triggers["pull_request"]; !exists {
				t.Fatal("on.pull_request is required to gate proposed changes")
			}
			if _, exists := triggers["workflow_dispatch"]; !exists {
				t.Fatal("on.workflow_dispatch is required as an operator backstop")
			}
		})
	}
}

func TestSecurityAnalysisKeepsScheduledDriftCoverage(t *testing.T) {
	for _, name := range []string{"codeql.yml", "security.yml"} {
		t.Run(name, func(t *testing.T) {
			workflow := loadWorkflow(t, name)
			triggers := mapping(t, workflow["on"], "on")
			schedules := sequence(t, triggers["schedule"], "on.schedule")
			if len(schedules) == 0 {
				t.Fatal("on.schedule is required to detect vulnerability and analysis drift")
			}
		})
	}
}
