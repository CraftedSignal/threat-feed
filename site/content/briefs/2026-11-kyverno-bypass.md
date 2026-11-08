---
brief_id: brief-2026-11-08-kyverno-bypass
event_id: brief-2026-11-08-kyverno-bypass
revision: 1
activity_at: "2026-11-08T15:28:43Z"
title: 'Kyverno: Authorization bypass in apiCall (CVE-2026-124440)'
slug: 2026-11-kyverno-bypass
description: Kyverno versions 1.19.1 contain an authorization bypass vulnerability in the apiCall namespace clamp that allows cross-namespace and cluster-scoped resource access via malformed percent-escapes in urlPath.
date: "2026-11-08T15:28:43Z"
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
cpes:
  - cpe:2.3:a:kyverno:kyverno:1.19.1:*:*:*:*:*:*:*
vendors:
  - Kyverno
products:
  - Kyverno (1.19.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can create namespaced Policies whose apiCall runs as the admission-controller ServiceAccount to read other namespaces resources and create mutating webhooks, escalating to cluster admin.
    confidence_band: high
cves:
  - id: CVE-2026-124440
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124440
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Kyverno to version 1.19.2 or later to address CVE-2026-124440
      owner: IT Operations
      due: 24h
      evidence: Kyverno from 1.19.1 before 1.19.2 contains an authorization bypass vulnerability
  hunt_leads:
    - lead: Identify Kyverno Policies using apiCall with potentially malformed percent-encoded characters in urlPath
      technique_id: T1068
      data_needed:
        - Kubernetes Policy resource definitions
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: allows namespace tenants to issue cross-namespace and cluster-scoped API requests by appending malformed percent-escapes to urlPath
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Kyverno 1.19.2
      owner: IT Operations
      addresses: CVE-2026-124440
      evidence: Kyverno from 1.19.1 before 1.19.2 contains an authorization bypass vulnerability
---

Kyverno versions 1.19.1 are affected by a vulnerability in the apiCall namespace clamp. An attacker can bypass authorization constraints by appending malformed percent-escapes to the urlPath parameter within an apiCall. This allows a user with restricted namespace access to issue requests that operate outside their namespace, potentially leveraging the privileges of the Kyverno admission-controller ServiceAccount.

## Impact
Successful exploitation allows a namespaced tenant to access resources across the cluster, including sensitive data in other namespaces. Attackers can create mutating webhooks, which leads to full cluster administrator privilege escalation.

## Recommendation
- Upgrade Kyverno to version 1.19.2 or later immediately.
- Audit existing Kyverno Policies for any apiCall usage that could be abused to target cross-namespace resources.
- Monitor Kyverno admission controller logs for abnormal API call patterns or unexpected cross-namespace requests.
