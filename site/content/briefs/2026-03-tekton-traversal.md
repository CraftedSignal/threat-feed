---
title: Tekton Pipelines Git Resolver Path Traversal Vulnerability
slug: 2026-03-tekton-traversal
description: The Tekton Pipelines git resolver is vulnerable to path traversal via the `pathInRepo` parameter, allowing arbitrary file reads from the resolver pod's filesystem, including ServiceAccount tokens.
date: "2026-03-24T00:16:29Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - tekton
  - path-traversal
  - kubernetes
  - cve-2026-33211
  - cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33211
rules:
  - title: Detect Suspicious ResolutionRequest Creation
    description: Detects the creation of ResolutionRequest objects, which could indicate attempts to exploit CVE-2026-33211.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Path Traversal in ResolutionRequest pathInRepo
    description: Detects path traversal attempts in ResolutionRequest objects by looking for '..' sequences in the pathInRepo parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

The Tekton Pipelines project provides Kubernetes-style resources for declaring CI/CD pipelines. A path traversal vulnerability exists in the git resolver component, tracked as CVE-2026-33211. This vulnerability affects Tekton Pipelines versions 1.0.0 and prior to 1.0.1, 1.3.3, 1.6.1, 1.9.2, and 1.10.2. An attacker with the ability to create `ResolutionRequests` (e.g., through `TaskRuns` or `PipelineRuns` that utilize the git resolver) can exploit this flaw to read any file from the resolver pod's file system. A successful exploit allows attackers to retrieve sensitive information, such as ServiceAccount tokens, which are base64-encoded and returned in `resolutionrequest.status.data`. The vulnerability has been patched in versions 1.0.1, 1.3.3, 1.6.1, 1.9.2, and 1.10.2. This poses a significant risk in multi-tenant environments where lateral movement and privilege escalation are possible.

## Attack Chain

1. An attacker gains the ability to create `TaskRuns` or `PipelineRuns` within a Tekton Pipelines environment.
2. The attacker crafts a malicious `ResolutionRequest` that leverages the git resolver.
3. Within the `ResolutionRequest`, the attacker injects a path traversal sequence into the `pathInRepo` parameter, such as "../../../../etc/passwd".
4. The git resolver attempts to resolve the resource using the provided path.
5. Due to the path traversal vulnerability, the resolver accesses the file specified by the attacker on the resolver pod's file system.
6. The contents of the accessed file are read by the resolver.
7. The resolver encodes the file content in base64.
8. The base64-encoded content is returned in the `resolutionrequest.status.data` field, allowing the attacker to retrieve the content. This can include sensitive files such as ServiceAccount tokens.

## Impact

Successful exploitation of CVE-2026-33211 allows attackers to read arbitrary files from the Tekton Pipelines resolver pod. This can lead to the compromise of sensitive information, including ServiceAccount tokens. If ServiceAccount tokens are compromised, attackers can potentially gain unauthorized access to Kubernetes resources, leading to privilege escalation, lateral movement within the cluster, and potential data exfiltration. The impact is especially high in multi-tenant environments.

## Recommendation

*   Upgrade Tekton Pipelines to versions 1.0.1, 1.3.3, 1.6.1, 1.9.2, or 1.10.2 or later to patch CVE-2026-33211.
*   Implement strict RBAC policies to limit the ability to create `TaskRuns` and `PipelineRuns` to only authorized users and service accounts.
*   Monitor Kubernetes API audit logs for suspicious `ResolutionRequest` creation events (see rule: "Detect Suspicious ResolutionRequest Creation").
*   Implement network policies to restrict network access from the resolver pod to only necessary resources.
