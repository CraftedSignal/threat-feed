---
title: Tekton Pipelines Git Resolver API Token Leak via ServerURL Manipulation (CVE-2026-40161)
slug: 2026-04-tekton-credential-leak
description: Tekton Pipelines versions 1.0.0 to 1.10.0 are vulnerable to credential access, where the Git resolver in API mode transmits the system-configured Git API token to a user-controlled serverURL, enabling token exfiltration via a malicious server.
date: "2026-04-22T12:00:00Z"
type: advisory
types:
  - advisory
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

Tekton Pipelines, a Kubernetes-style resource for declaring CI/CD pipelines, contains a vulnerability (CVE-2026-40161) in its git resolver component. Specifically, versions 1.0.0 to 1.10.0 are affected. When operating in API mode, the resolver inadvertently sends the system-configured Git API token (e.g., GitHub PAT, GitLab token) to a server specified by the user if the token parameter is omitted. This allows an attacker with TaskRun or PipelineRun creation privileges to exfiltrate the shared API token by directing the serverURL to an attacker-controlled endpoint. The vulnerability allows for the potential compromise of CI/CD pipelines and related infrastructure.

## Attack Chain

1. An attacker gains access to a Kubernetes tenant with permissions to create TaskRun or PipelineRun resources within Tekton Pipelines.
2. The attacker crafts a malicious TaskRun or PipelineRun configuration.
3. The configuration leverages the Tekton Pipelines git resolver in API mode.
4. The attacker omits the `token` parameter in the git resolver configuration, forcing the system to use the system-configured Git API token.
5. The attacker sets the `serverURL` parameter to an attacker-controlled endpoint.
6. Tekton Pipelines, upon execution of the TaskRun or PipelineRun, sends the system-configured Git API token to the attacker-controlled `serverURL`.
7. The attacker's server logs and captures the leaked Git API token.
8. The attacker uses the exfiltrated token to access and potentially compromise Git repositories or other services authenticated by the token.

## Impact

Successful exploitation of CVE-2026-40161 allows an attacker to steal the system-configured Git API token used by Tekton Pipelines. This could lead to unauthorized access to Git repositories, the modification of code, and the potential compromise of the entire CI/CD pipeline. Given Tekton's widespread adoption, a successful attack could affect numerous organizations using the vulnerable versions.

## Recommendation

*   Upgrade Tekton Pipelines to a version greater than 1.10.0 to remediate CVE-2026-40161.
*   Implement strict access controls within the Kubernetes cluster to limit TaskRun and PipelineRun creation privileges to authorized users only.
*   Monitor network traffic originating from Tekton Pipeline pods for connections to unusual or untrusted `serverURL` destinations as specified in CVE-2026-40161. Create a network connection rule for this.
*   Review Tekton Pipeline configurations for suspicious `serverURL` parameters using a file monitoring rule.
