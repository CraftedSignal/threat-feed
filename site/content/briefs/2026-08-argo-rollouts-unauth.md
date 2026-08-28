---
title: Unauthenticated Mutating Operations in Argo Rollouts Dashboard
slug: 2026-08-argo-rollouts-unauth
description: Argo Rollouts dashboard versions 1.10.0 and earlier expose sensitive, mutating operations without authentication, authorization, or CSRF protection when bound to all network interfaces.
date: "2026-08-28T21:35:17Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:argoproj:argo_rollouts:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - cloud-native
  - kubernetes
vendors:
  - Argo Project
products:
  - Argo Rollouts (<= 1.10.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The dashboard exposes mutating Rollout operations without authentication, authorization, or CSRF protection.
    confidence_band: high
cves:
  - id: CVE-2026-82277
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82277
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Platform Engineering
  immediate_actions:
    - action: Restrict network access to Argo Rollouts dashboard endpoints via network policies
      owner: Platform Engineering
      due: 24h
      evidence: Source states dashboard binds to all interfaces, exposing operations without authentication.
  mitigation_plan:
    - priority: immediate
      action: Isolate dashboard service behind an authenticated reverse proxy
      owner: IT Operations
      addresses: CVE-2026-82277
      evidence: Source highlights lack of authentication/authorization in dashboard.
---

Argo Rollouts versions 1.10.0 and earlier contain a critical vulnerability where the dashboard service binds to all network interfaces by default. This misconfiguration, combined with a lack of authentication, authorization, or CSRF protection on critical API endpoints, allows any attacker with network access to the dashboard instance to invoke unauthorized administrative actions. Attackers can leverage this to manipulate application deployments across all Kubernetes namespaces accessible via the operator's underlying kubeconfig. This flaw effectively grants remote, unauthenticated control over the entire rollout lifecycle, including deployment promotion, abortion, image modification, and restart operations. The impact is significant for organizations running Argo Rollouts in multi-tenant environments or environments where the dashboard is inadvertently exposed to broader network segments.

## Impact

Successful exploitation allows an unauthenticated attacker to arbitrarily modify application state within the cluster. By invoking operations like SetRolloutImage or PromoteRollout, an attacker can deploy malicious container images, interrupt legitimate service delivery, or disrupt automated release pipelines. The impact extends to all namespaces the dashboard's service account or operator kubeconfig can manage, potentially resulting in full cluster-wide service compromise.

## Recommendation

* Immediate: Restrict network access to the Argo Rollouts dashboard to authorized internal networks only, preferably behind a reverse proxy or VPN, until the software is patched.
* Update: Upgrade Argo Rollouts to the latest version once a fix is provided by the Argo Project to address the default binding configuration and lack of API security controls.
* Monitor: Review Kubernetes RBAC roles and cluster-wide permissions assigned to the Argo Rollouts operator to minimize the potential blast radius if the dashboard is compromised.
