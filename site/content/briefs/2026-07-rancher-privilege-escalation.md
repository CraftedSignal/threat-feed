---
title: Rancher Manager Privilege Escalation from Project Owner to Host (CVE-2026-41052)
slug: 2026-07-rancher-privilege-escalation
description: A critical privilege escalation vulnerability exists in Rancher Manager where a Project Owner can modify Pod Security Admission (PSA) labels on namespaces within their projects, allowing them to configure a namespace to use the privileged profile, which enables the deployment of privileged workloads that bypass standard container isolation, leading to host-level access and cluster privilege escalation.
date: "2026-07-03T10:31:28Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:suse:rancher:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - container
  - kubernetes
  - cloud
vendors:
  - SUSE
  - Rancher
products:
  - Rancher Manager < 2.12.10
  - Rancher Manager < 2.13.6
  - Rancher Manager < 2.14.2
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A vulnerability has been identified in Rancher Manager that allows users assigned the Project Owner role to modify Pod Security Admission (PSA) labels on namespaces within their projects... This can result in privilege escalation within the cluster environment.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1610
    technique_name: Deploy Container
    evidence: The user deploys privileged workloads within the namespace.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
    evidence: privileged containers disable core Kubernetes security protections, allowing workloads to bypass standard container isolation boundaries... Access to host-level resources, Container breakout, Cluster privilege escalation
    confidence_band: high
cves:
  - id: CVE-2026-41052
    cvss: 8.8
    epss: 0.0031
references:
  - https://github.com/advisories/GHSA-vx8h-4prv-g744
  - https://kubernetes.io/docs/concepts/security/pod-security-standards/
---

A critical privilege escalation vulnerability, identified as CVE-2026-41052, has been disclosed in Rancher Manager, affecting versions prior to `v2.12.10`, `v2.13.6`, and `v2.14.2`. This flaw allows users assigned the Project Owner role to maliciously modify Pod Security Admission (PSA) labels on namespaces they control. By doing so, an attacker can configure a namespace to utilize the 'privileged' PSA profile, effectively disabling core Kubernetes security protections. This enables the deployment of highly privileged workloads that can bypass standard container isolation boundaries. Exploitation of this vulnerability can lead to direct access to host-level resources, container breakout, and ultimately, cluster-wide privilege escalation, compromising affected nodes and their running workloads. Defenders need to prioritize patching or applying the specified workarounds to prevent this severe access vector.

## Attack Chain

1.  A legitimate user is granted "Cluster Member" access within Rancher Manager, providing them with initial access to the cluster environment.
2.  The user either creates a new project or is assigned ownership of an existing project, thereby receiving the "Project Owner" role.
3.  Leveraging their Project Owner role, the user creates a new namespace within their assigned project.
4.  Due to the vulnerability (CVE-2026-41052), the Project Owner modifies the Pod Security Admission (PSA) configuration for their newly created namespace.
5.  The attacker specifically sets the namespace's PSA profile to "privileged," which removes crucial security restrictions.
6.  Within this privileged namespace, the attacker deploys a containerized workload (e.g., a Kubernetes Pod) configured with elevated capabilities, such as `privileged: true` or host path mounts.
7.  This privileged workload bypasses standard container isolation boundaries, gaining direct access to the underlying host's resources and filesystem.
8.  From the compromised host, the attacker can achieve broader cluster privilege escalation, potentially affecting other nodes and control plane components.

## Impact

Exploitation of CVE-2026-41052 in Rancher Manager allows a malicious Project Owner to escalate privileges significantly within the Kubernetes cluster. The primary consequences include the deployment of privileged containers, which then grant access to host-level resources of the underlying nodes. This can lead to container breakout scenarios, bypassing typical isolation mechanisms and potentially compromising the host operating system. The ultimate result is cluster privilege escalation, where the attacker gains control over critical cluster components and data, compromising all workloads running on affected nodes and potentially the entire cluster's integrity and confidentiality.

## Recommendation

*   Patch CVE-2026-41052 immediately by upgrading Rancher Manager to `v2.12.10`, `v2.13.6`, `v2.14.2`, or newer.
*   If immediate patching is not possible, implement the recommended workaround: create a custom project role based on the existing Project Owner role, but explicitly restrict the allowed verbs for projects to only “`get`, `update`, `delete`, `patch`, `create`, `list`, `watch`, `deletecollection`” instead of the wildcard “`*`”. This prevents access to the `updatepsa` capability.
