---
title: Tekton Pipelines Git Resolver API Token Leak via User-Controlled ServerURL
slug: 2026-04-tekton-api-token-leak
description: The Tekton Pipelines git resolver in API mode leaks the system-configured Git API token to a user-controlled `serverURL` when the user omits the `token` parameter, allowing an attacker with TaskRun or PipelineRun creation permissions to exfiltrate the shared API token.
date: "2026-04-22T12:00:00Z"
type: coverage
types:
  - coverage
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

A vulnerability exists in Tekton Pipelines' git resolver (versions v1.0.0 through v1.10.0) where the system-configured Git API token is sent to a user-controlled `serverURL` when the user omits the `token` parameter. This allows a malicious tenant with TaskRun or PipelineRun create permissions to exfiltrate the shared API token (GitHub PAT, GitLab token, etc.) by pointing `serverURL` to an attacker-controlled endpoint. The attacker can then use this token to gain unauthorized access to private repositories, potentially exposing source code, secrets, and CI/CD configurations. This vulnerability is similar to GHSA-j5q5-j9gm-2w5c, where credentials could be exfiltrated. The vulnerability resides in the `ResolveAPIGit()` function within `pkg/resolution/resolver/git/resolver.go`.

## Attack Chain

1. Attacker gains permission to create TaskRuns or PipelineRuns within a Tekton Pipelines namespace.
2. Attacker crafts a malicious TaskRun or PipelineRun configuration.
3. The configuration specifies the git resolver in API mode.
4. The configuration omits the `token` parameter but includes a `serverURL` pointing to an attacker-controlled endpoint.
5. Tekton Pipelines executes the TaskRun or PipelineRun, triggering the git resolver.
6. The `ResolveAPIGit()` function retrieves the system-configured Git API token using `getAPIToken()`.
7. The function creates an SCM client pointed at the attacker-controlled `serverURL` with the system token as an `Authorization` header.
8. Subsequent API calls from the resolver to the attacker-controlled URL transmit the system token, allowing the attacker to capture it.

## Impact

Successful exploitation allows an attacker to exfiltrate the system Git API token (GitHub PAT, GitLab token, etc.). The exfiltrated token can be used to access private repositories, potentially leading to the exposure of sensitive information like source code, secrets, and CI/CD configurations.  This can lead to supply chain compromise, data breaches, or other unauthorized activities. All Tekton Pipeline instances running versions v1.0.0 through v1.10.0 are potentially vulnerable if a system-level API token is configured.

## Recommendation

*   **Do not configure a system-level API token** in the git resolver ConfigMap. Instead, require all users to provide their own tokens via the `token` parameter, as suggested in the advisory's workaround section.
*   **Restrict TaskRun creation** to limit which users or ServiceAccounts can create TaskRuns and PipelineRuns that use the git resolver, as recommended in the advisory's workaround section.
*   **Apply NetworkPolicy** to the `tekton-pipelines-resolvers` namespace to restrict outbound traffic to known-good Git servers only, mitigating the risk of token exfiltration to arbitrary `serverURL` values.
