---
title: External Secrets Operator Label Enforcement Bypass Leading to Secret Exfiltration
slug: 2026-10-external-secrets-bypass
description: A vulnerability in the External Secrets Operator enables authenticated users to bypass label enforcement checks in webhook generators, allowing unauthorized exfiltration of Kubernetes secrets to malicious URLs.
date: "2026-10-06T18:48:44Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:external-secrets:external_secrets:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - cloud-native
  - k8s
vendors:
  - External Secrets
products:
  - External Secrets Operator (>= 0.10.0, < 1.3.2)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: A user with the permission to create webhook generator can set the webhook generator to a victim' secret, and exfiltrate it to a malicious URL.
    confidence_band: high
cves:
  - id: CVE-2026-26287
    cvss: 7.1
references:
  - https://github.com/advisories/GHSA-q7hv-xx6h-q2x8
action_plan:
  priority: elevated
  owners:
    - DevOps
    - Security Operations
  immediate_actions:
    - action: Upgrade External Secrets Operator to version 1.3.2 or later
      owner: DevOps
      due: 48h
      evidence: Source advisory states fix released in 1.3.2
  mitigation_plan:
    - priority: immediate
      action: Restrict RBAC permissions for creation of Webhook generators
      owner: Security Operations
      addresses: CVE-2026-26287
      evidence: Source recommends restricting RBAC as a mitigation
---

External Secrets Operator is vulnerable to an authentication and authorization bypass affecting its `webhook` generator functionality. The issue arises from an incorrect initialization order in the provider's logic, which inadvertently disables the `EnforceLabels` flag after it has been configured. This flag is intended to ensure that only secrets explicitly labeled with `external-secrets.io/type: webhook` can be utilized by the webhook generator. 

By exploiting this defect, a low-privileged user or service account with the ability to create `Webhook` generator resources can reference any Kubernetes secret within the cluster, regardless of whether it carries the required security label. When the operator processes the request, it skips the validation check and transmits the secret data to an attacker-controlled endpoint defined in the webhook configuration. This affects External Secrets Operator versions 0.10.0 through 1.3.1. The fix was introduced in version 1.3.2.

## Impact

Successful exploitation allows for the exfiltration of sensitive Kubernetes secrets, including API keys, database credentials, or tokens stored within the cluster. This threat specifically targets clusters where users have delegated permissions to create webhook generators. If unauthorized actors gain access to this capability, they can extract credentials that were previously protected by namespace or label-based access control, potentially leading to privilege escalation or lateral movement within the environment.

## Recommendation

Prioritized actions for security teams:
- Upgrade the External Secrets Operator to version 1.3.2 or later to remediate CVE-2026-26287.
- Implement an admission policy using OPA Gatekeeper or Kyverno to explicitly enforce the presence of the `external-secrets.io/type=webhook` label on all secrets referenced by `Webhook` generator objects.
- Review RBAC configurations to strictly limit the `create` or `patch` permissions on `generators.external-secrets.io/v1alpha1` resources.
- Apply Kubernetes NetworkPolicies or service mesh egress filters to restrict the External Secrets Operator pod to only communicate with known, trusted webhook destinations.
