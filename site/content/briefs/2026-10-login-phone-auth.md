---
brief_id: brief-2026-10-29-login-phone-auth
event_id: brief-2026-10-29-login-phone-auth
revision: 1
activity_at: "2026-10-29T13:21:01Z"
title: 'Hamid Alinia Login with phone number: Authentication abuse (CVE-2026-115967)'
slug: 2026-10-login-phone-auth
description: The Login with phone number plugin for WordPress is vulnerable to authentication abuse due to weak authentication mechanisms, affecting versions up to and including 1.8.78.
date: "2026-10-29T13:21:01Z"
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
  validation_status: Needs environment validation
cpes:
  - cpe:2.3:a:hamid_alinia:login_with_phone_number:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - plugin
  - authentication-abuse
  - cve-2026-115967
vendors:
  - Hamid Alinia
products:
  - Login with phone number (<= 1.8.78)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: The plugin contains a weak authentication vulnerability that allows attackers to perform authentication abuse.
    confidence_band: high
cves:
  - id: CVE-2026-115967
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115967
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all WordPress installations and identify versions of Login with phone number
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects plugin up to 1.8.78
  hunt_leads:
    - lead: Identify abnormal authentication patterns within WordPress access logs related to phone verification endpoints
      technique_id: T1550
      data_needed:
        - Web access logs (access.log)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows authentication abuse
  mitigation_plan:
    - priority: immediate
      action: Disable or uninstall Login with phone number plugin
      owner: IT Operations
      addresses: CVE-2026-115967
      evidence: Plugin is vulnerable in versions <= 1.8.78
---

CVE-2026-115967 identifies a weak authentication vulnerability in the Hamid Alinia 'Login with phone number' WordPress plugin. This flaw allows unauthorized actors to perform authentication abuse. The vulnerability is confirmed to affect all versions of the plugin from inception through 1.8.78. No specific remediation version or patch announcement is currently detailed in the vulnerability disclosure.

## Impact

The vulnerability is rated with a CVSS v3.1 base score of 8.8, indicating a high potential for unauthorized access to affected WordPress instances.

## Recommendation

- Audit WordPress instances to determine if the 'Login with phone number' plugin is installed and running version 1.8.78 or earlier.
- Disable or remove the plugin until a security patch is provided by the developer.
- Monitor WordPress authentication logs for suspicious activity or anomalous login attempts involving phone-based authentication workflows.
