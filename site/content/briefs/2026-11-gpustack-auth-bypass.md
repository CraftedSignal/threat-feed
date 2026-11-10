---
brief_id: brief-2026-11-10-gpustack-auth-bypass
event_id: brief-2026-11-10-gpustack-auth-bypass
revision: 1
activity_at: "2026-11-10T16:35:03Z"
title: 'GPUStack: Missing authorization in cluster API proxy (CVE-2026-103002)'
slug: 2026-11-gpustack-auth-bypass
description: An authenticated user in GPUStack versions 2.2.0 to 2.2.1 can perform unauthorized actions on managed Kubernetes clusters by exploiting a missing authorization check in the Kubernetes API proxy handler.
date: "2026-11-10T16:35:03Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:gpustack:gpustack:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - authentication-bypass
  - kubernetes
  - cloud-native
vendors:
  - GPUStack
products:
  - gpustack (< 2.2.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated non-administrative user could access a Kubernetes cluster they are not authorized to access through GPUStack's Kubernetes API proxy.
    confidence_band: high
cves:
  - id: CVE-2026-103002
    cvss: 8.8
    epss: 0.0036
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-3hch-x692-6qj3
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade gpustack to v2.2.2 or later
      owner: IT Operations
      due: 24h
      evidence: Fixed in gpustack v2.2.2.
  hunt_leads:
    - lead: Identify unusual Kubernetes API calls originating from GPUStack worker node IPs or ServiceAccount identifiers
      technique_id: T1068
      data_needed:
        - Kubernetes API server audit logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The cluster_apiserver_proxy handler did not perform a resource-level authorization check before forwarding requests to the selected cluster.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to GPUStack instance
      owner: IT Operations
      addresses: CVE-2026-103002
      evidence: Restrict access to the GPUStack instance to trusted administrator accounts until upgrading.
---

GPUStack versions 2.2.0 through 2.2.1 contain a missing authorization vulnerability in the `cluster_apiserver_proxy` handler. This flaw allows an authenticated non-administrative user to bypass resource-level authorization checks when forwarding requests to a Kubernetes cluster. The vulnerability stems from the proxy handler failing to validate user permissions before forwarding traffic through a worker node using its associated Kubernetes ServiceAccount.

## Impact
An attacker can leverage the ServiceAccount permissions of the worker node to interact with the Kubernetes cluster API. Depending on the privileges assigned to that ServiceAccount, observed and potential impacts include unauthorized reading of Kubernetes resources, modification of existing workloads, disruption of services through resource deletion, and potential remote code execution by creating attacker-controlled workloads.

## Recommendation
- Upgrade `gpustack` to version `v2.2.2` or later immediately to patch CVE-2026-103002.
- Until the upgrade is deployed, restrict access to the GPUStack web interface and API to trusted administrative accounts only.
- Review Kubernetes RBAC roles and cluster role bindings associated with GPUStack worker ServiceAccounts to ensure they follow the principle of least privilege.
