---
title: IBM Instana Agent Operator RBAC Hijacking Vulnerability
slug: 2026-09-ibm-instana-rbac-hijack
description: An authenticated tenant can perform privilege escalation in Kubernetes clusters using IBM Instana Agent Operator (Build 1.0.303 through 1.0.323) by creating a malicious Custom Resource that overwrites shared cluster-level RBAC objects.
date: "2026-09-04T17:26:38Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:ibm:instana_agent:1.0.303:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:instana_agent:1.0.323:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - kubernetes
  - cloud
vendors:
  - IBM
products:
  - Instana Agent (1.0.303-1.0.323)
  - Instana Agent Operator
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated Kubernetes tenant can create a same-named InstanaAgent CR in an attacker-controlled namespace to silently overwrite the shared ClusterRoleBinding.
    confidence_band: high
cves:
  - id: CVE-2026-19274
    cvss: 9.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19274
action_plan:
  priority: immediate_escalation
  owners:
    - Infrastructure Security
    - Cloud Security
  immediate_actions:
    - action: Upgrade Instana Agent Operator to version post-1.0.323 to remediate CVE-2026-19274
      owner: Infrastructure Security
      due: 24h
      evidence: CVE-2026-19274 vulnerability scope
  mitigation_plan:
    - priority: immediate
      action: Restrict namespace-level access to the Instana Agent Operator CRD
      owner: Cloud Security
      addresses: CVE-2026-19274
      evidence: Vulnerability allows cross-namespace overwrite of cluster-scoped objects
---

IBM Observability with Instana Agent Operator (Build 1.0.303 through 1.0.323) contains a critical flaw in how it handles cluster-scoped RBAC objects for managed Kubernetes tenants. The operator keys specific RBAC resources solely by the name of the 'InstanaAgent' Custom Resource (CR) without incorporating namespace-based disambiguation. This design flaw allows an authenticated tenant within a multi-tenant Kubernetes environment to create a malicious 'InstanaAgent' CR using the same name as an existing, legitimate agent in a different namespace. Consequently, the operator mistakenly identifies the attacker-controlled resource as the intended target, allowing the attacker to silently overwrite shared 'ClusterRoleBinding' objects or delete them entirely. This behavior enables unauthorized privilege escalation or the permanent disruption of monitoring services for victim agents by revoking their cluster-level permissions.

## Impact

Successful exploitation allows a malicious tenant to hijack cluster-level RBAC permissions assigned to the Instana Agent Operator or disrupt monitoring for other tenants. In a multi-tenant Kubernetes cluster, this can lead to unauthorized access to cluster resources or significant denial-of-service of the observability platform, impacting the integrity and availability of security and performance monitoring data.

## Recommendation

Prioritized actions for security and infrastructure teams:

- Upgrade the IBM Instana Agent Operator to a version beyond 1.0.323 where namespace disambiguation for CRs is implemented to address CVE-2026-19274.
- Audit Kubernetes clusters for existing 'InstanaAgent' CRs across different namespaces that share identical names to identify potential conflict indicators.
- Implement restrictive Kubernetes RBAC policies that prevent untrusted tenants from creating or modifying custom resources associated with the Instana Agent Operator.
