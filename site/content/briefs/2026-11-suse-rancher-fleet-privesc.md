---
brief_id: brief-2026-11-02-suse-rancher-fleet-privesc
event_id: brief-2026-11-02-suse-rancher-fleet-privesc
revision: 1
activity_at: "2026-11-02T17:53:51Z"
title: 'SUSE Rancher Fleet: Privilege Escalation via Unauthorized Kubeconfig Reference (CVE-2026-94290)'
slug: 2026-11-suse-rancher-fleet-privesc
description: SUSE Rancher Fleet fails to restrict kubeconfig secret references, allowing a user to associate cluster definitions with management-level administrative credentials and execute arbitrary content with elevated privileges.
date: "2026-11-02T17:53:51Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: verified against NVD
cpes:
  - cpe:2.3:a:suse:rancher_fleet:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - kubernetes
  - cloud
vendors:
  - SUSE
products:
  - Rancher Fleet (0.16.0-0.16.3)
  - Rancher Fleet (0.15.0-0.15.8)
  - Rancher Fleet (0.14.0-0.14.12)
  - Rancher Fleet (0.13.0-0.13.17)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An ordinary user controls could be associated with administrative credentials for the management cluster itself, causing the controller to manage the management cluster on that user's behalf and to run that user's Fleet content there with elevated privileges.
    confidence_band: high
cves:
  - id: CVE-2026-94290
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94290
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  hunt_leads:
    - lead: Identify Fleet Cluster objects referencing secrets outside their own namespace
      technique_id: T1068
      data_needed:
        - Kubernetes audit logs / Fleet resource manifests
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The controller did not sufficiently restrict which kubeconfig secrets a Fleet Cluster object was allowed to reference.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Rancher Fleet to the latest secure version released by SUSE
      owner: IT Operations
      addresses: CVE-2026-94290
      evidence: CVE-2026-94290 advisory
---

SUSE Rancher Fleet clusters reference kubeconfig secrets for the deployment and management of agents on target clusters. A vulnerability exists where the controller does not properly validate or restrict which kubeconfig secrets a Fleet Cluster object may reference. An attacker with control over a namespace can configure a Fleet Cluster object to reference administrative kubeconfig secrets belonging to the management cluster. This results in the Fleet controller interacting with the management cluster using these administrative credentials, enabling the attacker to execute arbitrary Fleet content within the management cluster with elevated privileges.

## Impact

Successful exploitation allows for privilege escalation from a namespace-restricted user to administrative control over the management cluster, potentially leading to full cluster compromise.

## Recommendation

- Upgrade Rancher Fleet to a patched version once available from SUSE.
- Audit existing Fleet Cluster objects for suspicious kubeconfig secret references, particularly those pointing to secrets outside of the object's namespace.
- Restrict RBAC permissions for creating or modifying Fleet Cluster objects in non-administrative namespaces.
