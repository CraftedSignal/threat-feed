---
brief_id: brief-2026-11-03-manageengine-key-manager-plus-saml-bypass
event_id: brief-2026-11-03-manageengine-key-manager-plus-saml-bypass
revision: 1
activity_at: "2026-11-03T11:57:41Z"
title: ManageEngine Key Manager Plus SAML authentication bypass (CVE-2026-77800)
slug: 2026-11-manageengine-key-manager-plus-saml-bypass
description: ManageEngine Key Manager Plus versions prior to 7151 contain a SAML authentication bypass vulnerability that allows unauthenticated attackers to gain unauthorized access by presenting crafted SAML assertions.
date: "2026-11-03T11:57:41Z"
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
  validation_status: Validated against NVD source
cpes:
  - cpe:2.3:a:zohocorp:manageengine_key_manager_plus:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - authentication-bypass
  - saml
vendors:
  - ManageEngine
products:
  - Key Manager Plus (< 7151)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: ManageEngine Key Manager Plus versions before 7151 are vulnerable to a SAML authentication bypass that allows attackers to log in using SAML assertions meant for another service provider.
    confidence_band: high
cves:
  - id: CVE-2026-77800
    cvss: 7.7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77800
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade ManageEngine Key Manager Plus to version 7151 or later
      owner: IT Operations
      due: 48h
      evidence: ManageEngine Key Manager Plus versions before 7151 are vulnerable
  hunt_leads:
    - lead: Hunt for authentication events originating from non-standard SAML identity providers or unexpected Service Provider (SP) identifier mismatch in Key Manager Plus application logs
      technique_id: T1550
      data_needed:
        - Key Manager Plus application access/audit logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: vulnerability allows attackers to log in using SAML assertions meant for another service provider
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 7151
      owner: IT Operations
      addresses: CVE-2026-77800
      evidence: ManageEngine Key Manager Plus versions before 7151 are vulnerable
---

ManageEngine Key Manager Plus versions before 7151 are vulnerable to a SAML authentication bypass flaw. The vulnerability allows an attacker to gain unauthorized access by submitting a valid SAML assertion intended for a different service provider to the Key Manager Plus application. This bypass circumvents standard authentication mechanisms.

## Impact
Successful exploitation allows an unauthenticated attacker to bypass authentication and gain unauthorized access to the Key Manager Plus administrative interface.

## Recommendation
- Upgrade ManageEngine Key Manager Plus to version 7151 or later immediately to patch CVE-2026-77800.
- Review authentication logs for successful logins that originated from unusual sources or show inconsistencies in SAML assertion parameters if your environment utilizes SAML integration.
