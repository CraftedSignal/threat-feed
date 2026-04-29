---
title: Kyverno Service Account Token Leak via apiCall Servicecall Helper
slug: 2026-04-kyverno-token-leak
description: A vulnerability in Kyverno versions prior to 1.16.4 allows the Kyverno service account token to be sent to an attacker-controlled endpoint due to improper authorization header handling in the apiCall servicecall helper, affecting ClusterPolicy and global context usage.
date: "2026-04-21T19:16:18Z"
type: coverage
types:
  - coverage
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

Kyverno, a policy engine for cloud native platforms, is vulnerable to a confused deputy issue affecting versions prior to 1.16.4. The vulnerability stems from the `apiCall` `servicecall` helper's behavior of implicitly injecting an `Authorization: Bearer ...` header using the Kyverno controller service account token when a policy does not explicitly define an `Authorization` header. Since `context.apiCall.service.url` is controlled by the policy, an attacker can craft a malicious `ClusterPolicy` or leverage the global context to direct the Kyverno service account token to an attacker-controlled endpoint, potentially allowing for privilege escalation or unauthorized access to resources within the Kubernetes cluster. Namespaced policies are protected by the `namespaced urlPath` gate, limiting the scope to `ClusterPolicy` and global context. This issue is resolved in Kyverno version 1.16.4.

## Attack Chain

1.  Attacker crafts a malicious Kyverno `ClusterPolicy` or modifies global context data.
2.  The malicious policy or global context configures `context.apiCall.service.url` to point to an attacker-controlled endpoint.
3.  The crafted policy triggers an API call using the `apiCall` `servicecall` helper.
4.  The `apiCall` helper checks for an existing `Authorization` header in the policy definition.
5.  Finding no explicit `Authorization` header, the `apiCall` helper implicitly injects `Authorization: Bearer <kyverno-service-account-token>`.
6.  The API call, including the Kyverno service account token, is sent to the attacker-controlled endpoint defined in `context.apiCall.service.url`.
7.  Attacker captures the Kyverno service account token from the received API call.
8.  Attacker uses the stolen Kyverno service account token to authenticate to the Kubernetes API and perform unauthorized actions.

## Impact

Successful exploitation of this vulnerability allows an attacker to steal the Kyverno service account token. This token can then be used to impersonate the Kyverno controller and perform actions with its privileges within the Kubernetes cluster. The severity is rated high due to the potential for privilege escalation and unauthorized access to sensitive resources within the cluster. While the precise number of affected installations isn't specified, any Kyverno deployment prior to version 1.16.4 using `ClusterPolicy` or global context is potentially vulnerable.

## Recommendation

*   Upgrade Kyverno to version 1.16.4 or later to patch CVE-2026-40868.
*   Implement network policies to restrict outbound connections from the Kyverno controller pod to only trusted endpoints to limit the impact if the token is leaked.
*   Monitor Kubernetes audit logs for unusual API calls originating from the Kyverno service account, focusing on requests to external or untrusted endpoints (monitor via generic k8s audit logs).
