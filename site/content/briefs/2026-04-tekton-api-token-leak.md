---
title: Tekton Pipelines Git Resolver API Token Leak via User-Controlled ServerURL
slug: 2026-04-tekton-api-token-leak
description: The Tekton Pipelines git resolver in API mode leaks the system-configured Git API token to a user-controlled `serverURL` when the user omits the `token` parameter, allowing an attacker with TaskRun or PipelineRun creation permissions to exfiltrate the shared API token.
date: "2026-04-22T12:00:00Z"
severities:
  - high
tags:
  - tekton
  - git
  - credential-access
  - api-token
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-40161
    cvss: 7.7
references:
  - https://github.com/advisories/GHSA-wjxp-xrpv-xpff
  - https://github.com/tektoncd/pipeline/security/advisories/GHSA-j5q5-j9gm-2w5c
  - https://github.com/tektoncd/pipeline/issues/9608
  - https://github.com/tektoncd/pipeline/issues/9609
rules:
  - title: Detect Tekton TaskRun/PipelineRun Creation with User-Controlled ServerURL and Missing Token
    description: Detects the creation of Tekton TaskRuns or PipelineRuns that utilize the git resolver with a user-specified serverURL and a missing token parameter, indicating potential exploitation of CVE-2026-40161.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - auditd
      - linux
  - title: Detect Outbound Connection from tekton-pipelines-resolvers to Unusual Git Server
    description: This rule detects network connections initiated by the tekton-pipelines-resolvers namespace to a server that isn't the configured Git server, which is an indicator that an API token might be leaked.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A vulnerability exists in Tekton Pipelines' git resolver (versions v1.0.0 through v1.10.0) where the system-configured Git API token is sent to a user-controlled `serverURL` when the user omits the `token` parameter. This allows a malicious tenant with TaskRun or PipelineRun create permissions to exfiltrate the shared API token (GitHub PAT, GitLab token, etc.) by pointing `serverURL` to an attacker-controlled endpoint. The attacker can then use this token to gain unauthorized access to private…
