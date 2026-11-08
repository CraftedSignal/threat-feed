---
brief_id: brief-2026-11-08-kyverno-auth-bypass-47ac2f60
event_id: brief-2026-11-08-kyverno-auth-bypass-47ac2f60
revision: 1
activity_at: "2026-11-08T15:31:13Z"
title: 'Kyverno: Authorization bypass via variable injection (CVE-2026-124441)'
slug: 2026-11-kyverno-auth-bypass-47ac2f60
description: Kyverno versions before 1.19.2 are vulnerable to an authorization bypass allowing tenants to leverage the privileged background-controller to create or modify arbitrary resources across namespaces.
date: "2026-11-08T15:31:13Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:kyverno:kyverno:*:*:*:*:*:*:*:*
vendors:
  - Kyverno
products:
  - Kyverno (< 1.19.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can create a Policy and trigger ConfigMap in their own namespace, causing the privileged background-controller to write NetworkPolicies or RoleBindings into victim or kube-system namespaces.
    confidence_band: high
cves:
  - id: CVE-2026-124441
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124441
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Kyverno to 1.19.2 or later
      owner: IT Operations
      due: 48h
      evidence: Kyverno before 1.19.2 contains an authorization bypass vulnerability
  hunt_leads:
    - lead: Identify creation of privileged resources originated by the Kyverno background-controller service account in sensitive namespaces.
      technique_id: T1068
      data_needed:
        - Kubernetes Audit Logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: causing the privileged background-controller to write NetworkPolicies or RoleBindings into victim or kube-system namespaces
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 1.19.2
      owner: IT Operations
      addresses: CVE-2026-124441
      evidence: Kyverno before 1.19.2 contains an authorization bypass
---

Kyverno versions before 1.19.2 contain an authorization bypass vulnerability (CVE-2026-124441). Namespaced tenants can generate arbitrary Kubernetes resources by injecting variables into a generate rule's kind and namespace fields. This allows an attacker to influence the background-controller, which operates with elevated privileges, to write sensitive resources like NetworkPolicies or RoleBindings into target namespaces, including the kube-system namespace.

## Attack Chain

1. Attacker authenticates as a tenant with permissions to create Kyverno Policies within a controlled namespace.
2. Attacker crafts a malicious Kyverno generate rule using variable templating for the target kind and destination namespace.
3. Attacker creates a trigger object, such as a ConfigMap, within their own namespace to activate the rule.
4. The Kyverno background-controller identifies the rule and processes the templated fields.
5. The controller executes the generation logic using its elevated service account privileges.
6. The controller creates or modifies unauthorized resources in the target namespace (e.g., kube-system).

## Impact

An attacker can achieve unauthorized privilege escalation and lateral movement within a Kubernetes cluster by creating or modifying critical resources, effectively bypassing namespace boundaries and authorization controls.

## Recommendation

- Upgrade Kyverno to version 1.19.2 or later immediately.
- Audit existing Kyverno policies for use of variable templating in the generate rule "kind" and "namespace" fields.
- Restrict the ability to create Kyverno policies within namespaces to trusted service accounts or cluster administrators until the patch is applied.
