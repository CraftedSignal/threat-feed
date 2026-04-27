---
title: Kyverno ConfigMap Cross-Namespace Read RBAC Bypass (CVE-2026-22039 Incomplete Fix)
slug: 2026-04-kyverno-configmap-rbac-bypass
description: CVE-2026-22039 incompletely fixed a cross-namespace privilege escalation vulnerability in Kyverno's apiCall context, as the ConfigMap context loader still lacks namespace validation, allowing a namespace admin to read ConfigMaps from any namespace using Kyverno's privileged service account, leading to a complete RBAC bypass in multi-tenant Kubernetes clusters.
date: "2026-04-17T12:00:00Z"
severities:
  - high
tags:
  - kyverno
  - rbac-bypass
  - kubernetes
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
cves:
  - id: CVE-2026-22039
    cvss: 9.9
    epss: 0.00061
references:
  - https://github.com/advisories/GHSA-cvq5-hhx3-f99p
rules:
  - title: Detect Kyverno Policy Creating Cross-Namespace ConfigMap Context
    description: Detects Kyverno policies that attempt to read ConfigMaps from a different namespace, indicating a potential RBAC bypass attempt.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552.001
    data_sources:
      - file_event
      - linux
  - title: Detect ConfigMap Modification with Unusual Annotations
    description: Detects ConfigMap resources being modified with annotations containing suspicious keys, which could indicate data exfiltration.
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

This brief addresses a critical vulnerability in Kyverno version 1.17.0 (and earlier) related to cross-namespace ConfigMap access, stemming from an incomplete fix for CVE-2026-22039. While the original CVE addressed privilege escalation in Kyverno's `apiCall` context, the ConfigMap context loader (`pkg/engine/context/loaders/configmap.go`) still lacks namespace validation. This allows a namespace administrator to craft a Kyverno policy that reads ConfigMaps from any namespace, effectively…
