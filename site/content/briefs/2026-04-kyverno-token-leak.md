---
title: Kyverno Service Account Token Leak via API Call
slug: 2026-04-kyverno-token-leak
description: Kyverno's apiCall serviceCall helper implicitly injects the Kyverno controller service account token into requests when policies lack an explicit Authorization header, allowing exfiltration to attacker-controlled endpoints and unauthorized actions.
date: "2026-04-14T20:09:00Z"
type: advisory
types:
  - advisory
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
iocs:
  - type: url
    value: https://github.com/kyverno/kyverno
  - type: url
    value: https://github.com/kyverno/kyverno/blob/17aeb52337fd66adb0c8126213ba076612a287a7/pkg/engine/apicall/executor.go#L150-L173
  - type: url
    value: https://github.com/kyverno/kyverno/blob/17aeb52337fd66adb0c8126213ba076612a287a7/pkg/engine/apicall/apiCall.go#L67-L83
  - type: url
    value: https://github.com/user-attachments/files/25352288/poc.zip
  - type: url
    value: https://github.com/user-attachments/files/25352289/PR_DESCRIPTION.md
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

A vulnerability exists in Kyverno versions prior to 1.17.0 where the `apiCall` and `serviceCall` helpers automatically inject the Kyverno controller's service account token into outgoing requests. This occurs when a Kyverno policy does not explicitly define an `Authorization` header for the request. Because the destination URL for these API calls is policy-controlled via `context.apiCall.service.url`, a malicious actor could create or modify a `ClusterPolicy` or `GlobalContextEntry` to direct these requests—and thus the service account token—to an attacker-controlled endpoint. This vulnerability allows for token exfiltration and subsequent unauthorized actions, depending on the RBAC permissions granted to the Kyverno service account. This issue is limited to `ClusterPolicy` and global context usage, as namespaced policies are blocked from `servicecall` usage.

## Attack Chain

1.  Attacker gains the ability to create or modify `ClusterPolicy` objects, potentially by compromising a GitOps repository or controller managing Kyverno policies.
2.  Attacker crafts a malicious `ClusterPolicy` that uses the `apiCall` or `serviceCall` feature.
3.  The policy specifies a URL for the `context.apiCall.service.url` that points to an attacker-controlled endpoint designed to capture the incoming request.
4.  The crafted policy does not define an explicit `Authorization` header for the `apiCall` or `serviceCall`.
5.  When the policy is triggered, Kyverno's `executor.addHTTPHeaders` function detects the missing `Authorization` header.
6.  Kyverno reads the service account token from `/var/run/secrets/kubernetes.io/serviceaccount/token`.
7.  Kyverno injects the service account token into the request header as `Authorization: Bearer <token>`.
8.  The request, including the Kyverno service account token, is sent to the attacker-controlled endpoint, allowing the attacker to exfiltrate the token.

## Impact

Successful exploitation of this vulnerability results in the exfiltration of the Kyverno controller service account token. The severity of the impact depends on the RBAC roles and permissions assigned to the Kyverno service account within the Kubernetes cluster. With the stolen token, an attacker can perform any action that the Kyverno service account is authorized to perform, potentially leading to cluster-wide compromise, data breaches, or denial-of-service conditions. The number of affected clusters would depend on the number of Kyverno deployments using vulnerable versions.

## Recommendation

*   Upgrade Kyverno to version 1.17.0 or later to patch the vulnerability (go/github.com/kyverno/kyverno).
*   Implement monitoring to detect modifications to `ClusterPolicy` resources, especially those utilizing `apiCall` or `serviceCall` to arbitrary URLs, to quickly identify potentially malicious policy changes.
*   Deploy the provided Sigma rule to detect unexpected outbound network connections from the Kyverno pod that may indicate token exfiltration.
*   As a workaround, set explicit `Authorization` headers in all `apiCall` and `serviceCall` policies to prevent the implicit token injection (see workarounds).
