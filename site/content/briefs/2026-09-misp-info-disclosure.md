---
title: Information Disclosure Vulnerability in MISP
slug: 2026-09-misp-info-disclosure
description: An authenticated remote attacker can exploit a vulnerability in MISP to gain unauthorized access to sensitive information due to improper access controls.
date: "2026-09-07T13:33:52Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:misp-project:misp:*:*:*:*:*:*:*:*
  - cpe:2.3:a:craftcms:craft_cms:*:*:*:*:*:*:*:*
  - cpe:2.3:a:craftcms:craft_cms:4.0.0:rc1:*:*:*:*:*:*
  - cpe:2.3:a:craftcms:craft_cms:4.0.0:rc2:*:*:*:*:*:*
  - cpe:2.3:a:craftcms:craft_cms:4.0.0:rc3:*:*:*:*:*:*
  - cpe:2.3:a:craftcms:craft_cms:5.0.0:rc1:*:*:*:*:*:*
vendors:
  - MISP Project
products:
  - MISP (< 4.12.2)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: A vulnerability in MISP allows a remote, authenticated attacker to gain unauthorized access to sensitive information.
    confidence_band: high
cves:
  - id: CVE-2024-52293
    cvss: 7.2
    epss: 0.01358
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3203
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade MISP to 4.12.2 or later
      owner: IT Operations
      addresses: CVE-2024-52293
      evidence: Source reporting indicates a vulnerability in MISP requiring remediation
---

The MISP Project has disclosed a security vulnerability identified as CVE-2024-52293 affecting the Malware Information Sharing Platform (MISP). The vulnerability allows a remote, authenticated attacker to bypass intended access controls and access sensitive information within the platform. This issue impacts installations of MISP where insufficient authorization checks are performed on specific API endpoints or internal data structures. Because MISP is often used to store highly sensitive threat intelligence, unauthorized access to this data can lead to the exposure of proprietary intelligence, internal security configurations, and indicators of compromise. Organizations utilizing MISP should prioritize reviewing access logs for anomalous data access patterns and ensure their instances are updated to the latest security release addressing this vulnerability.

## Impact

Successful exploitation results in the unauthorized disclosure of sensitive threat intelligence stored within the MISP platform. This can jeopardize the security operations of affected organizations, as threat actors could gain visibility into active defensive measures, investigation metadata, or sensitive indicator feeds. The severity is compounded by the centralized nature of MISP in intelligence-sharing ecosystems.

## Recommendation

- Upgrade the MISP instance to the latest security version provided by the MISP Project that addresses CVE-2024-52293.
- Review internal MISP access logs for atypical user activity or excessive data export requests.
- Enforce the principle of least privilege for all user accounts accessing the MISP API and web interface.
