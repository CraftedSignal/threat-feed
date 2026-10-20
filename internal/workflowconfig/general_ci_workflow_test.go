package workflowconfig

import (
	"os"
	"path/filepath"
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
