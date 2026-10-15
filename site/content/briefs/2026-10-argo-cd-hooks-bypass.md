---
title: Argo CD AppProject Restriction Bypass via Delete Hooks
slug: 2026-10-argo-cd-hooks-bypass
description: Argo CD fails to validate AppProject destination and resource restrictions during PreDelete and PostDelete hook execution, allowing attackers to escalate privileges via the application-controller.
date: "2026-10-15T22:22:59Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:argoproj:argo_cd:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - argo-cd
  - kubernetes
  - gitops
vendors:
  - Argo Project
products:
  - Argo CD (v2.10.0 - v2.14.21)
  - Argo CD (v3.0.0 - v3.3.14)
  - Argo CD (v3.4.0 - v3.4.9)
  - Argo CD (v3.5.0 - v3.5.3)
  - Argo CD (v3.6.0-rc1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Argo CD fails to perform AppProject destination-namespace and resource permission checks when executing PreDelete and PostDelete lifecycle hooks.
    confidence_band: high
cves:
  - id: CVE-2026-77459
    cvss: 9.9
    epss: 0.0072
references:
  - https://github.com/advisories/GHSA-fmxq-cgp8-87wp
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-77459
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade to patched Argo CD versions (v3.6.0-rc2, v3.5.4, v3.4.10, v3.3.15)
      owner: IT Operations
      due: 24h
      evidence: Vendor patch recommendation
  mitigation_plan:
    - priority: immediate
      action: Review Git repository access permissions and restrict write access to sensitive Application manifests
      owner: IT Operations
      addresses: CVE-2026-77459
      evidence: Source workaround
---

Argo CD contains a security vulnerability (CVE-2026-77459) in how it handles lifecycle hooks during Application deletion. The application-controller skips mandatory AppProject validation checks, including destination namespace restrictions, server constraints, and resource allow/deny lists, when processing PreDelete and PostDelete hooks. Because these hooks are executed with the elevated credentials of the application-controller on the target cluster, an attacker with write access to a synchronized Git repository can define malicious resources that circumvent project-level isolation policies.

This vulnerability affects Argo CD v2.10.0 and all subsequent releases, including the v3.x branch up to recent versions. PreDelete and PostDelete hooks were introduced to extend application lifecycle management, but their implementation lacks the project-context validation applied to standard sync operations. The impact is significant because the application-controller typically possesses broad cluster-level permissions, enabling the creation of unauthorized cluster-scoped objects or resources in restricted namespaces upon application deletion.

## Attack Chain

1. Attacker obtains push access to a Git repository synchronized by an Argo CD Application.
2. Attacker modifies the application manifest in Git to include a PreDelete or PostDelete hook (e.g., a Kubernetes Job or ClusterRoleBinding).
3. Attacker defines the hook with metadata that violates the target AppProject's namespace or resource allow/deny lists.
4. Argo CD reconciles the repository and adds the delete finalizer to the Application, marking it as ready for hook execution.
5. An administrator or automated process triggers the deletion of the target Application.
6. The application-controller executes the attacker-defined hook using its own elevated credentials, bypassing AppProject validation.
7. The hook executes malicious code or creates forbidden cluster-scoped objects on the destination cluster.
8. The attacker achieves unauthorized resource creation or privilege escalation within the destination cluster environment.

## Impact

The vulnerability allows an attacker to bypass multi-tenancy and resource isolation boundaries defined in Argo CD. Successful exploitation enables unauthorized creation of cluster-scoped resources, such as ClusterRoleBindings, or the deployment of arbitrary objects in forbidden namespaces. The number of potentially impacted systems is high, as Argo CD is a widely deployed GitOps controller for Kubernetes environments. If exploited, an attacker could achieve full control over the destination cluster, leading to privilege escalation and potential exfiltration or persistence.

## Recommendation

* Upgrade Argo CD to the fixed versions immediately: v3.6.0-rc2, v3.5.4, v3.4.10, or v3.3.15.
* Audit Git repositories currently synchronized by Argo CD to detect suspicious hook definitions in existing application manifests.
* Implement the principle of least privilege for the application-controller service account to minimize the blast radius of potential hook-based exploitation.
* Restrict write access to Git repositories that back Applications deployed within sensitive, high-restriction AppProjects.
* Monitor application-controller logs for the creation of unauthorized cluster-scoped resources or resources in forbidden namespaces immediately following the deletion of an Application.
