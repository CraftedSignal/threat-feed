---
title: Unauthorized Command Execution via Self-Hosted GitHub Actions Runners
slug: 2026-09-github-runner-execution
description: Adversaries gaining unauthorized workflow trigger access can abuse GitHub Actions runners to execute arbitrary system commands, potentially leading to credential harvesting, reconnaissance, and CI/CD supply chain compromise.
date: "2026-09-18T19:18:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - execution
  - supply-chain
  - ci-cd
  - lotl
vendors:
  - GitHub
products:
  - GitHub Actions
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This rule detects potentially dangerous commands spawned by the GitHub Actions Runner.Worker process or by shell interpreters launched via a runner entrypoint script.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/execution_via_github_actions_runner.toml
  - https://www.elastic.co/blog/shai-hulud-worm-npm-supply-chain-compromise
  - https://socket.dev/blog/shai-hulud-strikes-again-v2
rules:
  - title: Detect Execution via GitHub Actions Runner
    description: Detects processes spawned by the GitHub Actions Runner worker process or runner entrypoint scripts, which may indicate malicious workflow execution.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to monitor for child processes spawned by runner workers.
      owner: Detection Engineering
      due: 48h
      evidence: Rule defined in brief.
  hunt_leads:
    - lead: Search for processes spawned by 'Runner.Worker' or 'entrypoint.sh' that involve network or infrastructure tools.
      technique_id: T1059
      data_needed:
        - Process creation logs with parent process context.
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source explicitly identifies these parent/child relationships as suspicious.
  mitigation_plan:
    - priority: medium_term
      action: Implement strict allowlisting for binary execution on self-hosted runner machines.
      owner: IT Operations
      addresses: Unauthorized execution
      evidence: Source recommends application whitelisting.
---

This threat concerns the abuse of self-hosted GitHub Actions runners to execute arbitrary commands on the host environment. When an adversary gains unauthorized access to a repository, they can modify or trigger malicious workflows that execute commands via the `Runner.Worker` process or bootstrapped runner entrypoint scripts. This technique is frequently observed in CI/CD supply chain compromises where attackers seek to leverage the runner's access to cloud infrastructure, secrets, or internal network segments. Attackers utilize a wide range of living-off-the-land (LotL) binaries, including shell interpreters, infrastructure CLIs (e.g., `kubectl`, `vault`, `gh`), and network utilities, to conduct reconnaissance, stage data, or maintain persistence. Protecting these runners is critical, as they often hold high-privilege credentials and network reachability to sensitive internal environments.

## Attack Chain

1. Attacker gains write access to a repository linked to a self-hosted runner, often via credential theft or compromised project maintainer accounts.
2. Attacker modifies an existing workflow file (e.g., in `.github/workflows/`) or creates a new one to include malicious command steps.
3. The GitHub Actions Runner service detects the workflow update and initiates a job, spawning the `Runner.Worker` process.
4. The `Runner.Worker` process or its associated entrypoint scripts (e.g., `entrypoint.sh`) executes the attacker-supplied commands.
5. The malicious process runs within the context of the runner service, executing binaries like `curl`, `kubectl`, or `base64` to interact with system resources.
6. The adversary performs activities such as credential theft (e.g., `vault kv get`), discovery (e.g., `nmap`), or exfiltration (e.g., `nc` to a remote listener).
7. Final objective: full compromise of the runner host or lateral movement into cloud-managed infrastructure.

## Impact

Successful exploitation allows attackers to gain code execution on runner hosts, which often have access to production secrets, cloud service provider credentials, and internal APIs. Victims face potential data exfiltration, compromise of software build pipelines (resulting in malicious downstream software distribution), and lateral movement into the broader corporate network.

## Recommendation

- Implement the provided detection logic to monitor for unexpected process execution originating from `Runner.Worker` or runner entrypoint scripts.
- Audit all GitHub Actions workflow configurations for repository modification history and unauthorized changes.
- Enforce strict environment variables and secret access policies for self-hosted runners to minimize the impact of a compromised workflow execution.
- Implement application allowlisting (e.g., AppLocker or equivalent Linux-based solutions) on runner hosts to prevent execution of unauthorized binaries.
- Move runners to isolated network segments with strictly defined egress filtering policies.
