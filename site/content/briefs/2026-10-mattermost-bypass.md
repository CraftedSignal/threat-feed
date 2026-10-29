---
brief_id: brief-2026-10-29-mattermost-bypass
event_id: brief-2026-10-29-mattermost-bypass
revision: 1
activity_at: "2026-10-29T18:36:35Z"
title: 'Mattermost Server: Security policy bypass (CVE-2026-93851)'
slug: 2026-10-mattermost-bypass
description: A security policy bypass vulnerability in Mattermost Server could allow an attacker to circumvent configured server security policies.
date: "2026-10-29T18:36:35Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: verified patches per vendor bulletin
cpes:
  - cpe:2.3:a:mattermost:mattermost_server:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - security-policy-bypass
vendors:
  - Mattermost
products:
  - Mattermost Server (11.7.x < 11.7.11, 11.8.x < 11.8.6, 11.9.x < 11.9.2)
cves:
  - id: CVE-2026-93851
    kev_status: unknown
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1409/
  - https://mattermost.com/security-updates/
  - https://www.cve.org/CVERecord?id=CVE-2026-93851
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Mattermost Server instances to the versions specified in MMSA-2026-00742 to resolve CVE-2026-93851.
      owner: IT Operations
      due: 48h
      evidence: Mattermost Security Bulletin MMSA-2026-00742
  hunt_leads:
    - lead: Audit Mattermost logs for unexpected changes to role-based access control or security configuration settings.
      data_needed:
        - Mattermost application audit logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows for security policy bypass
  mitigation_plan:
    - priority: immediate
      action: Patch affected Mattermost Server deployments to 11.7.11, 11.8.6, 11.9.2 or later.
      owner: IT Operations
      addresses: CVE-2026-93851
      evidence: CERT-FR advisory CERTFR-2026-AVI-1409
---

A security policy bypass vulnerability has been identified in Mattermost Server. The vulnerability is tracked as CVE-2026-93851 and impacts specific versions of the 11.7.x, 11.8.x, and 11.9.x branches. The vulnerability allows an attacker to circumvent security policies configured on the server instance.

## Impact

The vulnerability allows for the bypass of security policies enforced on the Mattermost Server, which may lead to unauthorized access or the circumvention of intended access controls.

## Recommendation

- Upgrade Mattermost Server installations to the patched versions as specified by the vendor in MMSA-2026-00742.
- Patch affected versions: 
 - 11.7.x to 11.7.11 or later
 - 11.8.x to 11.8.6 or later
 - 11.9.x to 11.9.2 or later
- Monitor audit logs for anomalous administrative or access control modification events that do not correlate with known administrator activity.
