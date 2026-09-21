---
title: CRI-O Checkpoint Restore Security Context Bypass
slug: 2026-09-crio-checkpoint-bypass
description: A vulnerability in CRI-O checkpoint restore allows an authenticated user to bypass Kubernetes security context enforcement by leveraging a malicious checkpointed container, leading to potential privilege escalation.
date: "2026-09-21T10:27:54Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - kubernetes
  - container-security
  - privilege-escalation
vendors:
  - Red Hat
  - CRI-O
products:
  - CRI-O (>= 1.34)
  - OpenShift Container Platform (>= 4.17)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The restored process may retain credentials, Linux capabilities, no_new_privs, and seccomp state from the checkpoint instead of enforcing the destination configuration.
    confidence_band: high
cves:
  - id: CVE-2026-92574
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92574
action_plan:
  priority: elevated
  owners:
    - Infrastructure Security
    - Platform Engineering
  immediate_actions:
    - action: Audit cluster configurations for the enablement of container checkpoint/restore.
      owner: Platform Engineering
      due: 48h
      evidence: Exploitation requires checkpoint restore functionality to be available.
  mitigation_plan:
    - priority: immediate
      action: Monitor for pod creation events from unauthorized users.
      owner: SOC
      addresses: CVE-2026-92574
      evidence: Exploitation requires permission to create a pod from a malicious checkpoint image.
---

CVE-2026-92574 describes a security flaw within the CRI-O container runtime checkpoint/restore mechanism. The vulnerability exists when a user with permissions to create pods utilizes a malicious checkpointed container image to initialize a new pod. During the restoration process, the runtime fails to properly apply the destination pod's intended Kubernetes security context.

Instead of enforcing the security settings defined in the new pod specification, the restored process inherits critical security state artifacts from the original checkpoint, including Linux capabilities, user credentials, no_new_privs flags, and seccomp profiles. This effectively allows an attacker to bypass container isolation and execute code with elevated privileges that were intended to be restricted. The vulnerability affects CRI-O version 1.34 and later, as well as Red Hat OpenShift Container Platform version 4.17 and subsequent releases. Impacted environments are those where checkpoint restore functionality is enabled and reachable by users capable of pod creation.

## Impact

Successful exploitation of this vulnerability permits unauthorized privilege escalation within a containerized environment. By bypassing established Kubernetes security contexts, an attacker can gain capabilities or permissions that were explicitly revoked in the destination pod configuration. This compromises container isolation boundaries, potentially allowing for cross-container lateral movement or host-level escalation if the inherited security state provides sufficient privileges. The scope of impact is limited to Kubernetes clusters utilizing affected CRI-O runtimes with checkpoint functionality enabled.

## Recommendation

Prioritized actions for security and platform engineering teams:

* Identify and audit all Kubernetes clusters running CRI-O 1.34+ or OCP 4.17+ where checkpoint/restore functionality is enabled.
* Restrict pod creation permissions (RBAC) to only trusted identities, as this is a prerequisite for exploitation of CVE-2026-92574.
* Monitor Kubernetes audit logs for pod creation requests involving unusual image sources or specific checkpoint-related APIs.
* Monitor for the deployment of pods with security contexts that conflict with the image's source characteristics if such metadata is traceable.
* Prepare to deploy official security patches from Red Hat or upstream CRI-O as soon as they become available to address CVE-2026-92574.
