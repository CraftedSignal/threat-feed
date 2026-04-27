---
title: PraisonAI GitHub Actions Credential Leakage Vulnerability (CVE-2026-40313)
slug: 2026-04-praisonai-artifact-leakage
description: 'PraisonAI versions 4.5.139 and below are vulnerable to credential leakage due to the ArtiPACKED attack, where GitHub Actions workflows using actions/checkout without persist-credentials: false write the GITHUB_TOKEN into the .git/config file, leading to potential exposure in uploaded artifacts and subsequent supply chain compromise.'
date: "2026-04-14T04:17:13Z"
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

PraisonAI, a multi-agent teams system, faces a critical vulnerability (CVE-2026-40313) in versions 4.5.139 and below. The vulnerability stems from the ArtiPACKED attack vector within GitHub Actions workflows. Specifically, the use of actions/checkout without setting `persist-credentials: false` causes the GITHUB_TOKEN to be written to the `.git/config` file. When subsequent workflow steps upload artifacts (build outputs, logs, test results, etc.), these tokens can be inadvertently included…
