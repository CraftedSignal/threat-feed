---
title: 'CVE-2026-100706: Path Traversal in Kyverno Policy apiCall Processing'
slug: 2026-09-kyverno-path-traversal
description: Kyverno versions before 1.19.1 contain a path traversal vulnerability in apiCall urlPath processing, enabling namespace-restricted users to perform unauthorized cluster-wide object manipulation via URL-encoded segments.
date: "2026-09-26T14:59:10Z"
lastmod: "2026-09-26T15:13:07Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:kyverno:kyverno:*:*:*:*:*:*:*:*
tags:
  - kyverno
  - path-traversal
  - kubernetes
  - privilege-escalation
  - vulnerability
  - cloud-native
vendors:
  - Kyverno
products:
  - kyverno (< 1.19.1)
  - Kyverno (1.16.0 - 1.19.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can exploit this by using percent-encoded directory traversal sequences to create MutatingWebhookConfiguration objects cluster-wide or PolicyException objects in the kyverno namespace, enabling privilege escalation to cluster admin.
    confidence_band: high
cves:
  - id: CVE-2026-100706
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100706
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100703
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Kyverno to 1.19.1
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-100706 mitigation
  mitigation_plan:
    - priority: immediate
      action: Upgrade Kyverno to 1.19.1 or later
      owner: IT Operations
      addresses: CVE-2026-100706
      evidence: Kyverno security advisory
updates:
  - at: "2026-09-26T15:13:07Z"
    level: L2
    summary: added coverage for Kyverno (1.16.0 - 1.19.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-100703
---

Kyverno versions prior to 1.19.1 are susceptible to a critical path traversal vulnerability within the Policy apiCall component. The vulnerability resides in the insufficient validation of URL-encoded path segments within the 'urlPath' field. This flaw allows a namespace-restricted tenant to bypass enforced namespace boundaries by using percent-encoded directory traversal sequences. When exploited, the attacker effectively elevates their privileges to that of the Kyverno admission-controller ServiceAccount. This level of access allows the attacker to create or modify sensitive cluster-wide resources, including MutatingWebhookConfiguration objects or PolicyException objects within the 'kyverno' namespace, ultimately resulting in full cluster-admin escalation.

## Impact

Successful exploitation allows a restricted tenant to break out of their assigned namespace context. This can lead to total cluster compromise through the injection of malicious webhook configurations, which intercept and modify arbitrary Kubernetes API requests, or by creating policy exceptions that disable security controls across the entire cluster.

## Recommendation

1. Upgrade all Kyverno deployments to version 1.19.1 or later immediately.
2. Audit current Policy resources for any 'apiCall' configurations utilizing 'urlPath' parameters until patches are applied.
3. Restrict permissions for creating or modifying Kyverno Policy resources to trusted cluster administrators to mitigate the potential impact of the vulnerability while pending upgrades.
