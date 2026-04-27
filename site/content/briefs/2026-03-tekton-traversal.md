---
title: Tekton Pipelines Git Resolver Path Traversal Vulnerability
slug: 2026-03-tekton-traversal
description: The Tekton Pipelines git resolver is vulnerable to path traversal via the `pathInRepo` parameter, allowing arbitrary file reads from the resolver pod's filesystem, including ServiceAccount tokens.
date: "2026-03-24T00:16:29Z"
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

The Tekton Pipelines project provides Kubernetes-style resources for declaring CI/CD pipelines. A path traversal vulnerability exists in the git resolver component, tracked as CVE-2026-33211. This vulnerability affects Tekton Pipelines versions 1.0.0 and prior to 1.0.1, 1.3.3, 1.6.1, 1.9.2, and 1.10.2. An attacker with the ability to create `ResolutionRequests` (e.g., through `TaskRuns` or `PipelineRuns` that utilize the git resolver) can exploit this flaw to read any file from the resolver…
