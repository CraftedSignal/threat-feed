---
title: GitHub CLI Partial Authentication Token Disclosure
slug: 2026-08-github-cli-token-disclosure
description: GitHub CLI contains an information exposure vulnerability in the gh auth status command that results in the partial disclosure of authentication tokens.
date: "2026-08-11T09:52:07Z"
lastmod: "2026-08-11T10:17:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - GitHub
products:
  - GitHub CLI
cves:
  - id: CVE-2026-64652
    cvss: 3.3
    epss: 0.00117
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64652
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64655
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Update GitHub CLI version across all developer endpoints and CI/CD runners.
      owner: IT Operations
      due: 72h
      evidence: Vendor patch recommendation for CVE-2026-64652.
  mitigation_plan:
    - priority: immediate
      action: Restrict read access to CI/CD and developer workstation log files capturing CLI output.
      owner: Security Operations
      addresses: CVE-2026-64652
      evidence: Mitigate the impact of potential partial token disclosure.
updates:
  - at: "2026-08-11T10:17:18Z"
    level: L1
    summary: added coverage for GitHub CLI
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64655
---

Microsoft has disclosed a security vulnerability, tracked as CVE-2026-64652, affecting the GitHub CLI (gh). The vulnerability resides within the gh auth status command, which, under certain conditions, may output partial authentication tokens to the standard output or logs. This information exposure poses a risk to security teams as it could reveal segments of sensitive credentials to unauthorized local users, logs, or secondary processes that capture command output. While the disclosure is partial, it may reduce the effort required for an attacker to brute-force or reconstruct valid authentication tokens. Organizations should ensure that CLI usage is managed in secure environments and that logs capturing command execution output are restricted to authorized personnel.

## Impact

Successful exploitation of this vulnerability could lead to the exposure of sensitive authentication material. This increases the risk of unauthorized access to GitHub repositories or associated cloud services if the partially disclosed tokens are utilized in credential-stuffing or reconstruction attacks. The scope of impact is limited to environments where the GitHub CLI is executed and its output is monitored or logged by third-party systems or local users with sufficient privileges.

## Recommendation

Update the GitHub CLI to the latest version as provided by GitHub to patch CVE-2026-64652. Audit automated scripts and CI/CD pipelines that invoke gh auth status to ensure that command output is not being written to insecure, publicly accessible, or centralized logging facilities.
