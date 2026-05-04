---
title: Argo Workflows Template Referencing Restriction Bypass
slug: 2026-05-argo-workflow-bypass
description: Argo Workflows has an incomplete fix for CVE-2026-31892, allowing bypass of templateReferencing restrictions to modify pod specifications, leading to potential privilege escalation and security context overrides.
date: "2026-05-04T20:11:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - argo-workflows
  - kubernetes
  - privilege-escalation
  - defense-evasion
vendors:
  - Argo
products:
  - argo-workflows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Controls
cves:
  - id: CVE-2026-31892
    cvss: 8.1
    epss: 0.0004
references:
  - https://github.com/advisories/GHSA-3775-99mw-8rp4
rules:
  - title: Argo Workflow Host Network Bypass
    description: Detects Argo Workflows attempting to bypass templateReferencing restrictions by setting hostNetwork to true.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Argo Workflow Service Account Override
    description: Detects Argo Workflows attempting to bypass templateReferencing restrictions by overriding the service account.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Argo Workflow Toleration Override
    description: Detects Argo Workflows attempting to bypass templateReferencing restrictions by overriding tolerations.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

Argo Workflows, a Kubernetes-native workflow engine, contains an incomplete fix for CVE-2026-31892. The initial patch blocked `podSpecPatch` modifications when `templateReferencing: Strict` was active. However, other fields within the WorkflowSpec that influence pod creation, such as `hostNetwork`, `serviceAccountName`, and `securityContext`, were not restricted. This allows a malicious user to bypass intended security controls and potentially escalate privileges within the Kubernetes cluster. Versions affected include those supporting the `templateReferencing` feature, specifically v4.0.2 and v3.7.11, which include the initial fix for CVE-2026-31892 but are still vulnerable to this bypass. This vulnerability exists because the check in `setExecWorkflow` only validates `HasPodSpecPatch()`, while other critical fields are applied directly to the pod specification. The bypass affects both `Strict` and `Secure` modes.

## Attack Chain

1.  Attacker gains `create Workflow` permission within the Argo Workflows environment.
2.  Attacker crafts a Workflow manifest that references a hardened WorkflowTemplate.
3.  Attacker sets `hostNetwork: true` (or other vulnerable fields like `securityContext`, `serviceAccountName`, `tolerations`, or `automountServiceAccountToken`) in the Workflow manifest.
4.  The Workflow is submitted, and the `setExecWorkflow` function in the Argo controller only checks for `podSpecPatch`.
5.  Due to the missing validation, the user-defined `hostNetwork: true` (or other vulnerable fields) is merged with the WorkflowTemplate specification.
6.  The `createWorkflowPod` function reads the merged specification and applies the `hostNetwork: true` setting directly to the pod specification, bypassing the intended restrictions.
7.  A pod is created with host networking enabled, granting the container access to the host's network namespace.
8.  The attacker can now access sensitive information or perform actions on the network as if they were running directly on the host.

## Impact

Successful exploitation allows an attacker to bypass the intended security restrictions imposed by Argo Workflows' `templateReferencing` feature. This can lead to privilege escalation, unauthorized access to network resources, and the potential to compromise other containers or nodes within the Kubernetes cluster. The impact is most significant in clusters that rely on Argo's Strict mode as the primary enforcement layer, as other Kubernetes-level controls like PodSecurity admission or OPA/Gatekeeper may not be in place to mitigate these bypasses.

## Recommendation

*   Deploy the Sigma rule `Argo Workflow Host Network Bypass` to detect workflows attempting to set `hostNetwork: true`, and tune for your environment.
*   Deploy the Sigma rule `Argo Workflow Service Account Override` to detect workflows attempting to override the service account.
*   Upgrade to a patched version of Argo Workflows that addresses CVE-2026-42296, ensuring that all WorkflowSpec fields that influence pod security posture are validated.
*   Implement Kubernetes-level controls, such as PodSecurity admission or OPA/Gatekeeper, to provide an additional layer of defense against unauthorized pod specification modifications.
