---
title: Repository Takeover Vulnerability in cal.com GitHub Actions (CVE-2024-58354)
slug: 2026-07-calcom-repo-takeover
description: A critical repository takeover vulnerability (CVE-2024-58354) exists in the cal.com (calcom/cal.diy) GitHub Actions workflows, allowing an attacker to submit a malicious pull request that executes arbitrary commands with write permissions to the repository, leading to full compromise.
date: "2026-07-23T22:20:33Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - github-actions
  - repository-takeover
  - vulnerability
  - cloud-security
vendors:
  - cal.com
  - GitHub
products:
  - cal.com (calcom/cal.diy repository)
  - GitHub Actions
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: check-types.yml then performs a 'dangerous' checkout of the attacker-submitted pull request code (via the dangerous-git-checkout action) and subsequently executes it (through yarn install and package.json scripts).
    confidence_band: high
cves:
  - id: CVE-2024-58354
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-58354
---

A critical repository takeover vulnerability, identified as CVE-2024-58354, affects the cal.com (specifically the `calcom` repository, later renamed `cal.diy`) project's GitHub Actions workflows. Attackers can exploit this by submitting a specially crafted pull request. The vulnerable `pr.yml` workflow, triggered by `pull_request_target` events, inadvertently grants its default write permissions (via the GITHUB_TOKEN) to a downstream workflow, `check-types.yml`. This `check-types.yml` then utilizes a "dangerous" checkout action to retrieve the attacker's submitted pull request code and subsequently executes it through `yarn install` and `package.json` scripts. This execution takes place with the repository's write-scoped token, enabling the attacker to perform arbitrary actions such as pushing commits, merging or mutating pull requests, adding or deleting comments, and deleting or force-pushing branches, effectively leading to a full compromise of the main branch and its associated codebase. No patched version is currently available for this vulnerability.

## Attack Chain

1. An attacker crafts a malicious pull request containing arbitrary commands within `package.json` scripts.
2. The attacker submits this pull request to the vulnerable cal.com repository.
3. The `pr.yml` GitHub Actions workflow is triggered by the `pull_request_target` event.
4. The `pr.yml` workflow, by design, passes its default repository write permissions (via `GITHUB_TOKEN`) to the `check-types.yml` workflow.
5. The `check-types.yml` workflow uses a "dangerous" checkout action to fetch the attacker's malicious pull request code.
6. `check-types.yml` executes `yarn install` and subsequent `package.json` scripts from the attacker-controlled code.
7. The attacker's arbitrary commands are executed with the repository's write-scoped `GITHUB_TOKEN`.
8. The attacker gains full control over the repository, capable of pushing commits, merging pull requests, and manipulating branches, leading to a complete repository compromise.

## Impact

The successful exploitation of CVE-2024-58354 results in a complete repository takeover for the affected cal.com GitHub repository. Attackers can gain the ability to inject malicious code, tamper with the software supply chain, delete or alter source code, and potentially compromise the integrity of releases. This could lead to backdoored software distributed to users, data exfiltration from the repository, or disruption of development workflows. As the main branch is affected and no patch is available, the risk remains high for organizations using or contributing to the cal.com project.

## Recommendation

* Review all GitHub Actions workflows, particularly `pr.yml` and `check-types.yml`, for the use of `pull_request_target` in conjunction with write permissions and dangerous checkout actions as described in CVE-2024-58354.
* Disable or refactor GitHub Actions workflows that use `pull_request_target` with default write permissions and perform untrusted code execution to mitigate CVE-2024-58354.
* Implement "least privilege" for GitHub Actions workflows, explicitly limiting permissions for GITHUB_TOKEN rather than relying on default write permissions.
* Audit existing GitHub Actions workflow logs for any suspicious activity or unexpected command execution that could indicate prior exploitation of CVE-2024-58354.
