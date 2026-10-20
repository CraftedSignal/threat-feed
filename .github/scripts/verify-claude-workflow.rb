#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"

repo_root = File.expand_path("../..", __dir__)
path = File.join(repo_root, ".github", "workflows", "claude-code-review.yml")
workflow = YAML.safe_load(File.read(path), aliases: true)

def assert(condition, message)
  abort "Claude workflow policy violation: #{message}" unless condition
end

analysis = workflow.fetch("jobs").fetch("claude-security-analysis")
assert(analysis.dig("permissions", "id-token") == "write", "analysis job must have OIDC access")
assert(analysis.dig("outputs", "workflow_changed") == "${{ steps.review-scope.outputs.workflow_changed }}",
       "analysis job must expose whether its own workflow changed")

steps = analysis.fetch("steps")
scope = steps.find { |step| step["id"] == "review-scope" }
assert(scope, "analysis job must detect changes to its own workflow")
assert(scope.fetch("run", "").include?(".github/workflows/claude-code-review.yml"),
       "workflow-change detection must be scoped to the Claude workflow")

review = workflow.fetch("jobs").fetch("claude-security-review")
publish = review.fetch("steps").find { |step| step["name"] == "Publish review and enforce result" }
assert(publish, "review job must publish or enforce the result")
assert(publish.dig("env", "WORKFLOW_CHANGED") == "${{ needs.claude-security-analysis.outputs.workflow_changed }}",
       "review job must receive the workflow-change result")
script = publish.fetch("run")
assert(script.include?('if [ -z "$REVIEW_OUTPUT" ]'), "empty structured output must be handled explicitly")
assert(script.include?('[ "$WORKFLOW_CHANGED" = "true" ]'),
       "empty output may only pass when the reviewed workflow itself changed")

puts "Claude workflow policy verified: OIDC, scoped self-change skip, structured output enforcement"
