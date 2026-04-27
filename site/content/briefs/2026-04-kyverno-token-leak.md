---
title: Kyverno Service Account Token Leak via apiCall Servicecall Helper
slug: 2026-04-kyverno-token-leak
description: A vulnerability in Kyverno versions prior to 1.16.4 allows the Kyverno service account token to be sent to an attacker-controlled endpoint due to improper authorization header handling in the apiCall servicecall helper, affecting ClusterPolicy and global context usage.
date: "2026-04-21T19:16:18Z"
severities:
  - high
tags:
  - kyverno
  - kubernetes
  - token-leak
  - cloud
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
cves:
  - id: CVE-2026-40868
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40868
rules:
  - title: Detect Kyverno Policy Creation with Suspicious apiCall URL
    description: Detects the creation of Kyverno policies that define an apiCall with a suspicious URL, potentially leading to token leakage.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552.006
    data_sources:
      - k8s_audit
      - kubernetes
  - title: Detect Kyverno Policy Update with Suspicious apiCall URL
    description: Detects updates to Kyverno policies that modify an apiCall to use a suspicious URL, potentially leading to token leakage.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552.006
    data_sources:
      - k8s_audit
      - kubernetes
rules_count: 2
---

Kyverno, a policy engine for cloud native platforms, is vulnerable to a confused deputy issue affecting versions prior to 1.16.4. The vulnerability stems from the `apiCall` `servicecall` helper's behavior of implicitly injecting an `Authorization: Bearer ...` header using the Kyverno controller service account token when a policy does not explicitly define an `Authorization` header. Since `context.apiCall.service.url` is controlled by the policy, an attacker can craft a malicious…
