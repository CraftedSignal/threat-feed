---
title: PraisonAI GitHub Actions Credential Leakage Vulnerability (CVE-2026-40313)
slug: 2026-04-praisonai-artifact-leakage
description: 'PraisonAI versions 4.5.139 and below are vulnerable to credential leakage due to the ArtiPACKED attack, where GitHub Actions workflows using actions/checkout without persist-credentials: false write the GITHUB_TOKEN into the .git/config file, leading to potential exposure in uploaded artifacts and subsequent supply chain compromise.'
date: "2026-04-14T04:17:13Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - credential-leakage
  - supply-chain
  - github-actions
  - cve-2026-40313
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1588
    technique_name: Obtain Capabilities
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1588
    technique_name: Obtain Capabilities
cves:
  - id: CVE-2026-40313
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40313
rules:
  - title: Detect GitHub Workflow Artifact Containing Git Config
    description: Detects GitHub workflow artifacts containing .git/config, indicating potential credential leakage
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1588
    data_sources:
      - file_event
      - linux
  - title: Detect Actions Runtime Token in Git Config
    description: Detects the presence of ACTIONS_RUNTIME_TOKEN within .git/config files, potentially indicating credential leakage.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1588
    data_sources:
      - file_event
      - linux
rules_count: 2
---

PraisonAI, a multi-agent teams system, faces a critical vulnerability (CVE-2026-40313) in versions 4.5.139 and below. The vulnerability stems from the ArtiPACKED attack vector within GitHub Actions workflows. Specifically, the use of actions/checkout without setting `persist-credentials: false` causes the GITHUB_TOKEN to be written to the `.git/config` file. When subsequent workflow steps upload artifacts (build outputs, logs, test results, etc.), these tokens can be inadvertently included. Given that PraisonAI is a public repository, any user with read access can download these artifacts and extract the leaked tokens. Successful exploitation allows attackers to push malicious code, poison releases and PyPI/Docker packages, steal repository secrets, and ultimately compromise the entire supply chain, affecting all downstream users. The issue is present across multiple workflow and action files within the `.github/workflows/` and `.github/actions/` directories. Version 4.5.140 addresses and resolves this vulnerability.

## Attack Chain

1.  Attacker gains read access to the public PraisonAI GitHub repository.
2.  Attacker identifies a GitHub Actions workflow that uploads artifacts.
3.  The workflow uses `actions/checkout` without `persist-credentials: false`, causing the GITHUB_TOKEN to be written to `.git/config`.
4.  The workflow uploads an artifact (e.g., build output, logs, test results) that includes the `.git/config` file.
5.  Attacker downloads the artifact.
6.  Attacker extracts the GITHUB_TOKEN from the `.git/config` file within the artifact.
7.  Attacker uses the leaked GITHUB_TOKEN to authenticate to the PraisonAI repository.
8.  Attacker leverages the compromised GITHUB_TOKEN to inject malicious code, poison releases/packages, steal secrets, or perform other malicious activities, leading to a supply chain compromise.

## Impact

Successful exploitation of CVE-2026-40313 in PraisonAI versions 4.5.139 and below can result in a severe supply chain compromise. Attackers can inject malicious code into the PraisonAI repository, poison releases and associated packages (PyPI, Docker), and steal sensitive repository secrets. This can lead to widespread distribution of malware to downstream users of PraisonAI, compromising their systems and data. The vulnerability affects any user relying on PraisonAI and its distributed components.

## Recommendation

*   Upgrade PraisonAI to version 4.5.140 or later to patch CVE-2026-40313.
*   Audit all GitHub Actions workflows in your organization to ensure that `actions/checkout` is used with `persist-credentials: false` to prevent credential leakage.
*   Monitor public repositories for inadvertently exposed configuration files containing credentials, and rotate potentially compromised tokens immediately.
*   Implement the Sigma rule "Detect GitHub Workflow Artifact Containing Git Config" to identify leaked git configurations.
