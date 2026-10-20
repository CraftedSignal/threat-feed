package workflowconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func loadSiteWorkflow(t *testing.T) map[string]any {
	t.Helper()

	path := filepath.Join("..", "..", ".github", "workflows", "site.yml")
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

func mapping(t *testing.T, value any, path string) map[string]any {
	t.Helper()
	result, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s: got %T, want mapping", path, value)
	}
	return result
}

func sequence(t *testing.T, value any, path string) []any {
	t.Helper()
	result, ok := value.([]any)
	if !ok {
		t.Fatalf("%s: got %T, want sequence", path, value)
	}
	return result
}

func TestSiteWorkflowBatchesProductionDeployments(t *testing.T) {
	workflow := loadSiteWorkflow(t)
	triggers := mapping(t, workflow["on"], "on")

	if _, exists := triggers["push"]; exists {
		t.Fatal("site workflow must not deploy once per content push")
	}

	schedules := sequence(t, triggers["schedule"], "on.schedule")
	if len(schedules) != 1 {
		t.Fatalf("on.schedule: got %d entries, want 1", len(schedules))
	}
	cron := mapping(t, schedules[0], "on.schedule[0]")["cron"]
	if cron != "7,22,37,52 * * * *" {
		t.Fatalf("on.schedule[0].cron: got %q, want offset 15-minute batching", cron)
	}
	if _, exists := triggers["workflow_dispatch"]; !exists {
		t.Fatal("on.workflow_dispatch is required for an immediate safe deployment")
	}

	concurrency := mapping(t, workflow["concurrency"], "concurrency")
	if concurrency["cancel-in-progress"] != true {
		t.Fatal("concurrency.cancel-in-progress must retire stale site builds")
	}
	group, _ := concurrency["group"].(string)
	if !strings.Contains(group, "pull_request") || !strings.Contains(group, "production") {
		t.Fatalf("concurrency.group %q must isolate PR validation from production", group)
	}
}

func TestSiteWorkflowValidatesPullRequestsWithoutDeploying(t *testing.T) {
	workflow := loadSiteWorkflow(t)
	triggers := mapping(t, workflow["on"], "on")
	pullRequest := mapping(t, triggers["pull_request"], "on.pull_request")
	paths := sequence(t, pullRequest["paths"], "on.pull_request.paths")

	wants := map[any]bool{
		"site/**":                    false,
		".github/workflows/site.yml": false,
	}
	for _, path := range paths {
		if _, wanted := wants[path]; wanted {
			wants[path] = true
		}
	}
	for path, found := range wants {
		if !found {
			t.Errorf("on.pull_request.paths is missing %q", path)
		}
	}

	jobs := mapping(t, workflow["jobs"], "jobs")
	validation := mapping(t, jobs["validate"], "jobs.validate")
	if condition, _ := validation["if"].(string); !strings.Contains(condition, "pull_request") {
		t.Fatalf("jobs.validate.if %q must restrict validation to pull requests", condition)
	}

	for _, jobName := range []string{"build", "deploy", "notify-subscribers"} {
		job := mapping(t, jobs[jobName], "jobs."+jobName)
		condition, _ := job["if"].(string)
		if !strings.Contains(condition, "refs/heads/main") {
			t.Errorf("jobs.%s.if %q must prevent non-main deployment side effects", jobName, condition)
		}
	}
}

func TestSiteWorkflowMinimizesProductionArtifactAndPermissions(t *testing.T) {
	workflow := loadSiteWorkflow(t)
	permissions := mapping(t, workflow["permissions"], "permissions")
	if len(permissions) != 1 || permissions["contents"] != "read" {
		t.Fatalf("workflow permissions: got %#v, want contents: read only", permissions)
	}

	jobs := mapping(t, workflow["jobs"], "jobs")
	build := mapping(t, jobs["build"], "jobs.build")
	buildPermissions := mapping(t, build["permissions"], "jobs.build.permissions")
	if buildPermissions["contents"] != "read" || buildPermissions["pages"] != "read" {
		t.Fatalf("jobs.build.permissions: got %#v, want contents and Pages read", buildPermissions)
	}

	deploy := mapping(t, jobs["deploy"], "jobs.deploy")
	deployPermissions := mapping(t, deploy["permissions"], "jobs.deploy.permissions")
	if deployPermissions["pages"] != "write" || deployPermissions["id-token"] != "write" {
		t.Fatalf("jobs.deploy.permissions: got %#v, want Pages and OIDC write", deployPermissions)
	}

	steps := sequence(t, build["steps"], "jobs.build.steps")
	foundUpload := false
	for index, rawStep := range steps {
		step := mapping(t, rawStep, "jobs.build.steps")
		uses, _ := step["uses"].(string)
		if !strings.Contains(uses, "actions/upload-pages-artifact") {
			continue
		}
		foundUpload = true
		with := mapping(t, step["with"], "jobs.build.steps.upload.with")
		if with["retention-days"] != 1 {
			t.Errorf("jobs.build.steps[%d].with.retention-days: got %#v, want 1", index, with["retention-days"])
		}
	}
	if !foundUpload {
		t.Fatal("jobs.build must upload the GitHub Pages artifact")
	}
}

func TestSiteWorkflowSkipsNoopScheduledBuilds(t *testing.T) {
	workflow := loadSiteWorkflow(t)
	jobs := mapping(t, workflow["jobs"], "jobs")
	changes := mapping(t, jobs["changes"], "jobs.changes")

	outputs := mapping(t, changes["outputs"], "jobs.changes.outputs")
	if outputs["site_changed"] == nil || outputs["previous_sha"] == nil {
		t.Fatalf("jobs.changes.outputs: got %#v, want site_changed and previous_sha", outputs)
	}

	build := mapping(t, jobs["build"], "jobs.build")
	if build["needs"] != "changes" {
		t.Fatalf("jobs.build.needs: got %#v, want changes", build["needs"])
	}
	condition, _ := build["if"].(string)
	if !strings.Contains(condition, "needs.changes.outputs.site_changed == 'true'") {
		t.Fatalf("jobs.build.if %q must skip scheduled builds with no site changes", condition)
	}

	notify := mapping(t, jobs["notify-subscribers"], "jobs.notify-subscribers")
	needs := sequence(t, notify["needs"], "jobs.notify-subscribers.needs")
	if len(needs) != 2 || needs[0] != "changes" || needs[1] != "deploy" {
		t.Fatalf("jobs.notify-subscribers.needs: got %#v, want [changes deploy]", needs)
	}
}

func TestSiteWorkflowHugoCacheTracksEveryTailwindSource(t *testing.T) {
	workflow := loadSiteWorkflow(t)
	jobs := mapping(t, workflow["jobs"], "jobs")

	for _, jobName := range []string{"validate", "build"} {
		job := mapping(t, jobs[jobName], "jobs."+jobName)
		steps := sequence(t, job["steps"], "jobs."+jobName+".steps")
		foundCache := false
		for _, rawStep := range steps {
			step := mapping(t, rawStep, "jobs."+jobName+".steps")
			uses, _ := step["uses"].(string)
			if !strings.Contains(uses, "actions/cache") {
				continue
			}
			foundCache = true
			with := mapping(t, step["with"], "jobs."+jobName+".steps.cache.with")
			key, _ := with["key"].(string)
			for _, source := range []string{"site/layouts/**", "site/content/**"} {
				if !strings.Contains(key, source) {
					t.Errorf("jobs.%s Hugo cache key %q does not track Tailwind source %q", jobName, key, source)
				}
			}
			if _, restoresStaleCache := with["restore-keys"]; restoresStaleCache {
				t.Errorf("jobs.%s Hugo cache can restore resources built from stale Tailwind sources", jobName)
			}
		}
		if !foundCache {
			t.Errorf("jobs.%s must cache Hugo resources", jobName)
		}
	}
}

func TestSiteWorkflowValidatesOnlyChangedPublicArtifacts(t *testing.T) {
	workflow := loadSiteWorkflow(t)
	jobs := mapping(t, workflow["jobs"], "jobs")

	for _, tt := range []struct {
		jobName string
		base    string
	}{
		{jobName: "validate", base: "github.event.pull_request.base.sha"},
		{jobName: "build", base: "needs.changes.outputs.previous_sha"},
	} {
		t.Run(tt.jobName, func(t *testing.T) {
			job := mapping(t, jobs[tt.jobName], "jobs."+tt.jobName)
			steps := sequence(t, job["steps"], "jobs."+tt.jobName+".steps")

			checkoutFound := false
			validationIndex := -1
			buildIndex := -1
			sitemapIndex := -1
			for i, rawStep := range steps {
				step := mapping(t, rawStep, "jobs."+tt.jobName+".steps")
				uses, _ := step["uses"].(string)
				if strings.Contains(uses, "actions/checkout") {
					checkoutFound = true
					with := mapping(t, step["with"], "checkout.with")
					if with["fetch-depth"] != 0 {
						t.Errorf("checkout.fetch-depth = %#v, want 0", with["fetch-depth"])
					}
				}
				name, _ := step["name"].(string)
				run, _ := step["run"].(string)
				switch name {
				case "Validate changed public artifacts":
					validationIndex = i
					env := mapping(t, step["env"], "changed validation env")
					base, _ := env["BASE_SHA"].(string)
					if !strings.Contains(base, tt.base) {
						t.Errorf("BASE_SHA %q does not use %s", base, tt.base)
					}
					for _, required := range []string{"git diff --name-only -z", "read -r -d ''", "go run ./cmd/feedcheck", "site/content/briefs/*.md", "site/static/stix/*.json"} {
						if !strings.Contains(run, required) {
							t.Errorf("changed validation is missing %q", required)
						}
					}
				case "Build site":
					buildIndex = i
				case "Validate generated sitemap":
					sitemapIndex = i
					if !strings.Contains(run, "go run ./cmd/feedcheck --generated-site site/public") {
						t.Errorf("sitemap validation command = %q", run)
					}
				}
			}
			if !checkoutFound {
				t.Error("full-history checkout is missing")
			}
			if validationIndex < 0 || buildIndex < 0 || validationIndex >= buildIndex {
				t.Errorf("changed artifact validation (%d) must precede site build (%d)", validationIndex, buildIndex)
			}
			if sitemapIndex <= buildIndex {
				t.Errorf("generated sitemap validation (%d) must follow site build (%d)", sitemapIndex, buildIndex)
			}
		})
	}
}
