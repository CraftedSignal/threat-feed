---
title: Red Hat Multicluster Engine Confused Deputy Vulnerability
slug: 2026-08-mce-confused-deputy
description: An authenticated tenant can exploit CVE-2026-73266 in the Red Hat Multicluster Engine clusterclaims-controller to perform a cross-tenant cluster join, enabling the unauthorized injection of workloads and policies.
date: "2026-08-13T18:56:27Z"
lastmod: "2026-08-19T18:38:23Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2026-73266
  - kubernetes
  - privilege-escalation
  - multitenancy
  - cloud-native
  - vulnerability
  - cve-2026-66794
vendors:
  - Red Hat
products:
  - Multicluster Engine for Kubernetes
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated tenant can exploit this vulnerability... to force a cluster to join a ManagedClusterSet belonging to another tenant.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: By manipulating URL path segments, the attacker can proxy requests to arbitrary services across any managed cluster.
    confidence_band: high
cves:
  - id: CVE-2026-73266
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73266
  - https://access.redhat.com/security/cve/CVE-2026-73266
  - https://bugzilla.redhat.com/show_bug.cgi?id=2514217
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66794
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch Multicluster Engine components to address CVE-2026-73266
      owner: IT Operations
      due: 48h
      evidence: Vendor advisory (CVE-2026-73266)
  mitigation_plan:
    - priority: immediate
      action: Deploy admission control policies to validate ClusterClaim label modifications
      owner: Security Engineering
      addresses: CVE-2026-73266
      evidence: Vulnerability root cause (CWE-441)
updates:
  - at: "2026-08-19T18:38:23Z"
    level: L2
    summary: added coverage for Multicluster Engine for Kubernetes
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-66794
---

A security flaw (CVE-2026-73266) exists within the clusterclaims-controller component of Red Hat Multicluster Engine (MCE) for Kubernetes. This vulnerability, categorized as a 'Confused Deputy' (CWE-441), allows an authenticated tenant within a multi-tenant environment to manipulate ClusterClaim labels. By improperly influencing the controller's logic, an attacker can force a cluster to join a ManagedClusterSet belonging to a different tenant. This unauthorized association breaks tenant isolation boundaries, providing the attacker the ability to push malicious policies or workloads into another tenant's environment. The vulnerability has a CVSS 3.1 score of 7.1, highlighting the potential for significant cross-tenant privilege escalation and impact on cluster integrity.

## Attack Chain

1. Attacker authenticates as a legitimate, lower-privileged tenant within the shared Multicluster Engine environment.
2. Attacker interacts with the Kubernetes API to modify ClusterClaim resource objects.
3. Attacker injects or updates specific ClusterClaim labels designed to target a victim ManagedClusterSet.
4. The vulnerable clusterclaims-controller observes the modified labels.
5. Due to insufficient validation, the controller incorrectly associates the attacker-controlled cluster with the victim's ManagedClusterSet.
6. The attacker leverages the cross-tenant membership to perform administrative actions.
7. Attacker executes API calls to push unauthorized policies or malicious container workloads into the victim's cluster.

## Impact

Successful exploitation results in a complete breach of multi-tenant isolation. Attackers can gain control over clusters they do not own, leading to unauthorized workload deployment, policy manipulation, and potential exfiltration of sensitive data residing in the victim's managed cluster environment.

## Recommendation

Prioritized, concrete actions for security operations and platform teams:
- Apply the latest security patches for the Multicluster Engine for Kubernetes provided by Red Hat to resolve CVE-2026-73266.
- Audit Kubernetes API audit logs for unusual modification patterns involving ClusterClaim resources where the user context does not match the target ClusterSet namespace.
- Implement restrictive Kubernetes Admission Controllers (e.g., OPA Gatekeeper or Kyverno) to enforce strict validation of label sets on ClusterClaim resources, preventing users from modifying critical system labels.
- Review RBAC policies to ensure that tenants are restricted from modifying ClusterClaim labels that influence cluster-level scheduling or grouping.
