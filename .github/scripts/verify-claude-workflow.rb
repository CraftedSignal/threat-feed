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
steps = analysis.fetch("steps")
checkout = steps.find { |step| step["name"] == "Checkout repository" }
assert(checkout, "analysis job must check out the repository")
assert(checkout.dig("with", "fetch-depth") != 0, "analysis job must not fetch full repository history")

review = workflow.fetch("jobs").fetch("claude-security-review")
publish = review.fetch("steps").find { |step| step["name"] == "Publish review and enforce result" }
assert(publish, "review job must publish or enforce the result")
script = publish.fetch("run")
assert(script.include?('if [ -z "$REVIEW_OUTPUT" ]'), "empty structured output must be handled explicitly")
assert(!script.include?("WORKFLOW_CHANGED"), "workflow self-changes must not bypass security review")
assert(script.match?(/if \[ -z "\$REVIEW_OUTPUT" \]; then\s+echo [^\n]+\s+exit 1\s+fi/m),
       "empty structured output must fail closed")

puts "Claude workflow policy verified: OIDC, shallow checkout, fail-closed output enforcement"
