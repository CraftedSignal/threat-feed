---
title: Kyverno ConfigMap Cross-Namespace Read RBAC Bypass (CVE-2026-22039 Incomplete Fix)
slug: 2026-04-kyverno-configmap-rbac-bypass
description: CVE-2026-22039 incompletely fixed a cross-namespace privilege escalation vulnerability in Kyverno's apiCall context, as the ConfigMap context loader still lacks namespace validation, allowing a namespace admin to read ConfigMaps from any namespace using Kyverno's privileged service account, leading to a complete RBAC bypass in multi-tenant Kubernetes clusters.
date: "2026-04-17T12:00:00Z"
type: advisory
types:
  - advisory
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

This brief addresses a critical vulnerability in Kyverno version 1.17.0 (and earlier) related to cross-namespace ConfigMap access, stemming from an incomplete fix for CVE-2026-22039. While the original CVE addressed privilege escalation in Kyverno's `apiCall` context, the ConfigMap context loader (`pkg/engine/context/loaders/configmap.go`) still lacks namespace validation. This allows a namespace administrator to craft a Kyverno policy that reads ConfigMaps from any namespace, effectively bypassing RBAC controls. This vulnerability impacts multi-tenant Kubernetes clusters, particularly those running Azure Kubernetes Service (AKS) or other managed Kubernetes services using Kyverno. Exploitation requires a namespace admin to create a Kyverno Policy resource in their namespace.  A successful exploit allows the attacker to exfiltrate sensitive data, such as database credentials and API keys, stored in ConfigMaps across the cluster.

## Attack Chain

1. An attacker with namespace admin privileges creates a service account and role binding within their assigned namespace.
2. The attacker deploys a Kyverno `Policy` resource within their namespace. This policy is crafted to exploit the vulnerability in the ConfigMap context loader.
3. The policy specifies `context.configMap.namespace` to target a ConfigMap in a different, victim namespace.  This step leverages the lack of namespace validation in `pkg/engine/context/loaders/configmap.go`.
4. The policy includes a `mutate` rule designed to extract data from the targeted ConfigMap and embed it into annotations of another ConfigMap within the attacker's namespace.
5. The attacker triggers the policy by creating or modifying a ConfigMap (e.g., `trigger-cm`) in their own namespace. This triggers Kyverno's admission controller.
6. Kyverno, running with a privileged service account (cluster-wide `view` role), fetches the ConfigMap from the victim namespace based on the attacker's policy.
7. The `mutate` rule in the policy executes, copying the contents of the stolen ConfigMap data into annotations of the trigger ConfigMap.
8. The attacker retrieves the modified `trigger-cm` ConfigMap and extracts the exfiltrated secrets from the annotations.

## Impact

Successful exploitation of this vulnerability allows a namespace administrator to bypass Kubernetes RBAC and read ConfigMaps from any namespace within the cluster. This can lead to the exfiltration of sensitive data such as database credentials, API keys, and other secrets stored in ConfigMaps. The impact is most severe in multi-tenant environments where namespace isolation is critical for security.  This vulnerability affects any Kubernetes cluster running Kyverno v1.17.0 (and earlier) with namespace-scoped Policy creation enabled. A successful attack violates the principle of least privilege and breaks multi-tenancy guarantees.

## Recommendation

*   Deploy the Sigma rule `Detect Kyverno Policy Creating Cross-Namespace ConfigMap Context` to identify potentially malicious policies.
*   Apply the namespace validation fix suggested in the advisory to `configmap.NewConfigMapLoader()`.  Specifically, ensure the resolved namespace in the ConfigMap context matches the policy's namespace (`pkg/engine/context/loaders/configmap.go`).
*   Audit other Kyverno context loaders (`globalReference`, `imageRegistry`, `variable`) for similar missing namespace validation patterns.
*   Upgrade to a patched version of Kyverno as soon as it is released. Refer to the Kyverno release notes for the fix version.
