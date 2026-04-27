---
title: Kyverno Service Account Token Leak via API Call
slug: 2026-04-kyverno-token-leak
description: Kyverno's apiCall serviceCall helper implicitly injects the Kyverno controller service account token into requests when policies lack an explicit Authorization header, allowing exfiltration to attacker-controlled endpoints and unauthorized actions.
date: "2026-04-14T20:09:00Z"
severities:
  - high
tags:
  - kyverno
  - token-leak
  - cloud
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://github.com/advisories/GHSA-q93q-v844-jrqp
  - https://github.com/kyverno/kyverno
  - https://github.com/kyverno/kyverno/blob/17aeb52337fd66adb0c8126213ba076612a287a7/pkg/engine/apicall/executor.go#L150-L173
  - https://github.com/kyverno/kyverno/blob/17aeb52337fd66adb0c8126213ba076612a287a7/pkg/engine/apicall/apiCall.go#L67-L83
  - https://github.com/user-attachments/files/25352288/poc.zip
  - https://github.com/user-attachments/files/25352289/PR_DESCRIPTION.md
ioc_counts:
  url: 5
rules:
  - title: Detect Outbound Connection from Kyverno Pod
    description: Detects outbound network connections originating from the Kyverno pod, which could indicate potential token exfiltration.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552.001
    data_sources:
      - network_connection
      - linux
  - title: Detect ClusterPolicy Creation/Update with apiCall
    description: Detects the creation or update of ClusterPolicy resources that utilize the apiCall or serviceCall functionality, which could be a precursor to token exfiltration.
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

A vulnerability exists in Kyverno versions prior to 1.17.0 where the `apiCall` and `serviceCall` helpers automatically inject the Kyverno controller's service account token into outgoing requests. This occurs when a Kyverno policy does not explicitly define an `Authorization` header for the request. Because the destination URL for these API calls is policy-controlled via `context.apiCall.service.url`, a malicious actor could create or modify a `ClusterPolicy` or `GlobalContextEntry` to direct…
