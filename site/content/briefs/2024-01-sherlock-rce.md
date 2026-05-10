---
title: sherlock-project/sherlock GitHub Actions RCE via pull_request_target Injection (CVE-2026-44590)
slug: 2024-01-sherlock-rce
description: A command injection vulnerability, identified as CVE-2026-44590, exists in the `validate_modified_targets.yml` GitHub Actions workflow of sherlock-project/sherlock. A malicious pull request can trigger arbitrary command execution in the privileged CI context, allowing attackers to exfiltrate the GITHUB_TOKEN and auto-approve the malicious PR without human interaction, effectively leading to a supply chain compromise.
date: "2024-01-03T17:30:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - github_actions
  - rce
  - supply_chain
vendors:
  - sherlock-project
products:
  - sherlock-project/sherlock
  - github.com
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.001
    technique_name: 'Unsecured Credentials: Cloud Instance Metadata API'
references:
  - https://sploitus.com/exploit?id=B265A4A6-887B-55F2-A0B7-038269601502
  - https://nstsec.com/en/posts/sherlock-rce-pull-request-target-cve-2026-44590/
  - https://github.com/sherlock-project/sherlock/security/advisories
  - https://nvd.nist.gov/vuln/detail/CVE-2026-44590
  - https://vulners.com/cve/CVE-2026-44590
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=B265A4A6-887B-55F2-A0B7-038269601502
  - type: url
    value: https://nstsec.com/en/posts/sherlock-rce-pull-request-target-cve-2026-44590/
  - type: url
    value: https://github.com/sherlock-project/sherlock/security/advisories
  - type: url
    value: https://nvd.nist.gov/vuln/detail/CVE-2026-44590
  - type: url
    value: https://vulners.com/cve/CVE-2026-44590
ioc_counts:
  url: 5
rules:
  - title: Detect Suspicious Sherlock GitHub Actions Workflow Activity
    description: Detects suspicious activity within Sherlock GitHub Actions workflows, specifically looking for command execution that attempts to exfiltrate secrets.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - execution
    techniques:
      - T1059.004
      - T1552.001
    data_sources:
      - process_creation
      - linux
  - title: Detect OAST Callback from GitHub Actions Workflow
    description: Detects outbound network connections from GitHub Actions workflows to known OAST (Out-of-Band Application Security Testing) services.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

CVE-2026-44590 is a critical command injection vulnerability found in the `validate_modified_targets.yml` GitHub Actions workflow of the sherlock-project/sherlock repository. Discovered and reported by Astaruf, this vulnerability allows any GitHub user to open a pull request that triggers arbitrary command execution within the privileged Continuous Integration (CI) environment. The vulnerability stems from the `pull_request_target` event, which, without proper input sanitization, permits the injection of malicious commands into the workflow. This exploit allows attackers to exfiltrate the `GITHUB_TOKEN` and automatically approve malicious pull requests, potentially leading to supply chain compromise without any human review. The proof-of-concept (PoC) automates the entire attack chain, highlighting the severity and ease of exploitation of this vulnerability.

## Attack Chain

1.  Attacker forks the `sherlock-project/sherlock` repository.
2.  Attacker creates a malicious branch with a crafted payload designed to inject commands into the `validate_modified_targets.yml` workflow.
3.  The attacker opens a pull request (PR) targeting the `master` branch of their fork, triggering the `pull_request_target` event.
4.  The GitHub Actions workflow executes the injected payload, which can include commands to exfiltrate sensitive information.
5.  The injected payload extracts the `GITHUB_TOKEN` from the workflow environment by reading `git config --list`.
6.  The stolen `GITHUB_TOKEN` is used to authenticate against the GitHub API.
7.  The attacker uses the stolen token to automatically approve the malicious pull request via the GitHub API, specifically the `POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews` endpoint.
8.  The malicious PR is merged, resulting in a supply chain compromise.

## Impact

Successful exploitation of CVE-2026-44590 can lead to a full supply chain compromise. An attacker could inject malicious code into the `sherlock-project/sherlock` repository (or forks thereof), potentially affecting all users of the software. The automated nature of the attack, involving token exfiltration and automatic PR approval, significantly increases the risk, reducing the need for manual interaction.  The impact is substantial as it allows for code injection into the project's codebase, potentially affecting all downstream users and dependencies.

## Recommendation

*   Monitor GitHub Actions workflow execution logs for unusual command invocations, particularly those involving `git config --list`, using a webserver rule on product `linux` that examines HTTP request headers.
*   Implement input validation and sanitization in GitHub Actions workflows, particularly when using the `pull_request_target` trigger, to prevent command injection as described in CVE-2026-44590.
*   Enforce strict branch protection rules and require code review by multiple trusted developers before merging any pull requests, even those approved by GitHub Actions.
*   Deploy the Sigma rule `Detect Suspicious Sherlock GitHub Actions Workflow Activity` to detect potential exploitation attempts by monitoring process creation events.
*   Review and audit existing GitHub Actions workflows for similar vulnerabilities and apply necessary security patches or mitigations.
