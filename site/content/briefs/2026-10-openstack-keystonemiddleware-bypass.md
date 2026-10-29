---
brief_id: brief-2026-10-29-openstack-keystonemiddleware-bypass
event_id: brief-2026-10-29-openstack-keystonemiddleware-bypass
revision: 1
activity_at: "2026-10-29T15:29:07Z"
title: 'OpenStack keystonemiddleware: Access control bypass via X-Service-Token (CVE-2026-115642)'
slug: 2026-10-openstack-keystonemiddleware-bypass
description: A vulnerability in OpenStack keystonemiddleware allows attackers to bypass access_rules using a malicious X-Service-Token, resulting in unauthorized access to restricted resources.
date: "2026-10-29T15:29:07Z"
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
  validation_status: Source verified; standard patch recommendations provided.
cpes:
  - cpe:2.3:a:openstack:keystonemiddleware:*:*:*:*:*:*:*:*
vendors:
  - OpenStack
products:
  - keystonemiddleware (<10.9.2, >=10.10.0 <10.12.2, >=11.0.0 <12.0.1, >=13.0.0 <13.0.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A vulnerability in the keystonemiddleware component of OpenStack allows an attacker to bypass access_rules using a specially crafted X-Service-Token.
    confidence_band: high
cves:
  - id: CVE-2026-115642
    kev_status: unknown
references:
  - https://seclists.org/oss-sec/2026/q4/434
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: 'Upgrade keystonemiddleware to patched versions: 10.9.2, 10.12.2, 12.0.1, or 13.0.2.'
      owner: IT Operations
      due: 48h
      evidence: Vulnerability remediation requires upgrading to the provided non-vulnerable versions.
  hunt_leads:
    - lead: Identify anomalous X-Service-Token headers in OpenStack service logs.
      technique_id: T1190
      data_needed:
        - OpenStack Keystone / middleware access logs
        - HTTP header logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability involves manipulation of the X-Service-Token header.
  mitigation_plan:
    - priority: immediate
      action: Apply security patches or upgrade keystonemiddleware to versions >=10.9.2, >=10.12.2, >=12.0.1, or >=13.0.2.
      owner: IT Operations
      addresses: CVE-2026-115642
      evidence: Upgrading the component is the documented fix for this CVE.
---

A vulnerability (CVE-2026-115642) exists in the OpenStack keystonemiddleware component. The flaw allows an attacker to bypass established access_rules by manipulating the X-Service-Token header, leading to unauthorized access to restricted resources. Affected versions include those <10.9.2, 10.10.0-10.12.1, 11.0.0-12.0.0, and 13.0.0-13.0.1.

## Impact
Successful exploitation allows for the bypass of access control restrictions, potentially exposing sensitive OpenStack service resources to unauthorized entities.

## Recommendation
- Upgrade OpenStack keystonemiddleware to a patched version (>=10.9.2, >=10.12.2, >=12.0.1, or >=13.0.2).
- Review OpenStack logs for requests containing anomalous X-Service-Token headers targeting sensitive endpoints.
