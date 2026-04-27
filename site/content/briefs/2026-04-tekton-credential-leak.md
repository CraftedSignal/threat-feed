---
title: Tekton Pipelines Git Resolver API Token Leak via ServerURL Manipulation (CVE-2026-40161)
slug: 2026-04-tekton-credential-leak
description: Tekton Pipelines versions 1.0.0 to 1.10.0 are vulnerable to credential access, where the Git resolver in API mode transmits the system-configured Git API token to a user-controlled serverURL, enabling token exfiltration via a malicious server.
date: "2026-04-22T12:00:00Z"
severities:
  - high
tags:
  - tekton
  - credential-access
  - cve-2026-40161
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
cves:
  - id: CVE-2026-40161
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40161
  - https://github.com/tektoncd/pipeline/issues/9608
  - https://github.com/tektoncd/pipeline/issues/9609
  - https://github.com/tektoncd/pipeline/security/advisories/GHSA-wjxp-xrpv-xpff
ioc_counts:
  email: 1
  url: 3
rules:
  - title: Tekton Pipeline Suspicious ServerURL Connection
    description: Detects network connections from Tekton Pipeline pods to unusual serverURL destinations, potentially indicating CVE-2026-40161 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.001
    data_sources:
      - network_connection
      - linux
  - title: Tekton Pipeline Suspicious ServerURL Configuration
    description: Detects Tekton Pipeline configurations with suspicious serverURL parameters, potentially indicating CVE-2026-40161 exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Tekton Pipelines, a Kubernetes-style resource for declaring CI/CD pipelines, contains a vulnerability (CVE-2026-40161) in its git resolver component. Specifically, versions 1.0.0 to 1.10.0 are affected. When operating in API mode, the resolver inadvertently sends the system-configured Git API token (e.g., GitHub PAT, GitLab token) to a server specified by the user if the token parameter is omitted. This allows an attacker with TaskRun or PipelineRun creation privileges to exfiltrate the shared…
