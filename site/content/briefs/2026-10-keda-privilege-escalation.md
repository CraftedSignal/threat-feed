---
title: KEDA Privilege Escalation via TriggerAuthentication
slug: 2026-10-keda-privilege-escalation
description: A namespace-level administrator can manipulate the KEDA operator to send its highly-privileged cluster ServiceAccount token to a tenant-controlled destination, resulting in full cluster-wide privilege escalation.
date: "2026-10-15T22:22:51Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:kedacore:keda:*:*:*:*:*:*:*:*
vendors:
  - KEDA
products:
  - keda-operator (<= 2.20.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A namespace admin who creates a TriggerAuthentication and a ScaledObject in their own namespace can make the KEDA operator send its own ServiceAccount token to a tenant-controlled URL.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The cluster-wide batch/jobs create lets the attacker run a workload in any namespace whose Pod Security Admission level permits it.
    confidence_band: high
cves:
  - id: CVE-2026-77524
    cvss: 9.9
  - id: CVE-2025-68476
    epss: 0.00554
references:
  - https://github.com/advisories/GHSA-637c-6jxx-4rwm
  - https://github.com/kedacore/keda
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade KEDA to version 2.21.0 or later
      owner: IT Operations
      due: 24h
      evidence: Source states affected version <= 2.20.0
  mitigation_plan:
    - priority: immediate
      action: Restrict creation of TriggerAuthentication resources to cluster-admin
      owner: Security Operations
      addresses: CVE-2026-77524
      evidence: Preconditions require tenant to hold create on triggerauthentications.keda.sh
---

KEDA version 2.20.0 and earlier contains a critical vulnerability (CVE-2026-77524) that allows a namespace-level administrator to escalate privileges to cluster-admin. The issue resides in how the `TriggerAuthentication` resource processes HashiCorp Vault authentication requests. Because the destination address for Vault is user-controlled and remains unvalidated, an attacker can point the KEDA operator to a malicious, tenant-controlled server. When the operator attempts to authenticate, it incorrectly defaults to using its own highly-privileged ServiceAccount token. The existing content filter, designed to mitigate CVE-2025-68476, merely verifies that the credential appears to be a Kubernetes JWT, which the operator's own token satisfies. Consequently, the operator sends its token to the attacker, providing the tenant with full cluster-wide permissions, including reading all Secrets and deploying arbitrary jobs across the entire cluster.

## Attack Chain

1. The attacker, possessing namespace-admin rights, deploys a listener service within their namespace designed to capture HTTP request bodies and impersonate a HashiCorp Vault server.
2. The attacker creates a `TriggerAuthentication` custom resource, setting the `hashiCorpVault.address` field to the URI of the malicious listener.
3. The attacker creates a `ScaledObject` in their namespace and references the `TriggerAuthentication` resource in the `authenticationRef` field.
4. The KEDA operator reconciles the `ScaledObject` and triggers the authentication workflow against the attacker's listener.
5. The KEDA operator sends its internal ServiceAccount token (authenticated as `keda-operator`) within an HTTP request body to the listener.
6. The attacker captures the raw ServiceAccount token from the listener logs.
7. The attacker uses the exfiltrated ServiceAccount token to authenticate to the Kubernetes API, granting cluster-wide read/write permissions.
8. The attacker performs impact activities, such as exfiltrating cluster-wide secrets or executing arbitrary jobs in sensitive namespaces (e.g., `kube-system`).

## Impact

The vulnerability allows for complete cluster compromise. Successful exploitation grants an attacker the permissions of the `keda-operator` ServiceAccount, which includes full cluster-wide access to secrets, the ability to modify admission configurations, and the privilege to create or delete workloads across all namespaces. This facilitates unauthorized data access and persistence across the environment.

## Recommendation

* Upgrade to KEDA 2.21.0 or later immediately to address CVE-2026-77524.
* Audit Kubernetes RBAC roles in multi-tenant environments to restrict the ability to create or modify `TriggerAuthentication` and `ScaledObject` resources to trusted principals only.
* Monitor cluster API access logs for anomalous usage of the `keda-operator` ServiceAccount, specifically focusing on cross-namespace secret access or job creation by unauthorized users.
