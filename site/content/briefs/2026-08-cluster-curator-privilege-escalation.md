---
title: Local Privilege Escalation in cluster-curator-controller via ClusterCurator Resources
slug: 2026-08-cluster-curator-privilege-escalation
description: A vulnerability in the cluster-curator-controller component allows a local user to escalate privileges to cluster-wide control by submitting a malformed ClusterCurator resource.
date: "2026-08-12T20:49:57Z"
type: advisory
types:
  - advisory
severities:
  - critical
products:
  - cluster-curator-controller
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A local user, by creating a ClusterCurator resource with a specific naming convention, can trigger the creation of a cluster-scoped ClusterRoleBinding.
    confidence_band: high
cves:
  - id: CVE-2026-73269
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73269
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review Kubernetes RBAC and Audit logs for unauthorized ClusterRoleBinding creation
      owner: SOC
      due: 24h
      evidence: Privilege escalation grants broad permissions including access to secrets.
  mitigation_plan:
    - priority: immediate
      action: Restrict ClusterCurator resource creation via admission webhooks
      owner: IT Operations
      addresses: CVE-2026-73269
      evidence: Exploit relies on creating a ClusterCurator resource.
---

The cluster-curator-controller component contains a critical vulnerability (CVE-2026-73269) that enables local privilege escalation within Kubernetes-based environments. An attacker with existing namespace-local access can exploit this flaw by submitting a ClusterCurator resource object configured with a specific naming convention. The controller incorrectly processes this resource, resulting in the unauthorized creation of a cluster-scoped ClusterRoleBinding. This misconfiguration grants the attacker excessive permissions across the entire cluster, effectively elevating their access from a limited namespace scope to full administrative control. Impacted organizations are at risk of unauthorized access to sensitive secrets, modification of cluster configurations, and the potential destruction of hosted clusters or node pools. Because the exploit relies on the creation of legitimate K8s objects, defenders must focus on monitoring for anomalous resource naming patterns and unauthorized ClusterRoleBinding creation.

## Attack Chain

1. Attacker establishes initial access to the cluster within a restricted namespace.
2. Attacker identifies the cluster-curator-controller presence within the environment.
3. Attacker crafts a malicious ClusterCurator resource object with a target-specific naming convention.
4. Attacker applies the resource to their local namespace via `kubectl apply` or Kubernetes API calls.
5. The cluster-curator-controller observes the new resource and attempts to process its configuration.
6. Controller logic fails to validate the resource name, causing it to escalate permissions.
7. Controller creates a ClusterRoleBinding with cluster-scoped administrative privileges.
8. Attacker leverages the resulting ClusterRoleBinding to exfiltrate secrets or delete node pools.

## Impact

Successful exploitation leads to full cluster-wide privilege escalation. Attackers can access and exfiltrate highly sensitive secrets, manipulate critical cluster resources, or delete hosted clusters and node pools, potentially causing complete infrastructure compromise and widespread service disruption.

## Recommendation

* Monitor Kubernetes audit logs for the creation of `ClusterRoleBinding` resources.
* Audit existing `ClusterCurator` resources for anomalous naming conventions that deviate from documented naming standards.
* Implement admission control policies to restrict the ability of low-privileged users to create or modify `ClusterCurator` resources.
* Review the `cluster-curator-controller` logs for unexpected resource handling errors related to `CVE-2026-73269`.
