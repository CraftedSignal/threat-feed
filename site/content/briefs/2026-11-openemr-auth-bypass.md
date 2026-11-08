---
brief_id: brief-2026-11-08-openemr-auth-bypass
event_id: brief-2026-11-08-openemr-auth-bypass
revision: 1
activity_at: "2026-11-08T15:28:53Z"
title: 'OpenEMR: Authentication bypass and token replay via OneTimeAuth (CVE-2026-124445)'
slug: 2026-11-openemr-auth-bypass
description: OpenEMR versions 7.0.1 through 8.3.x contain an authentication bypass vulnerability where service_auth tokens are not revoked and PIN verification lacks rate limiting, enabling session hijacking and unauthorized access to PHI.
date: "2026-11-08T15:28:53Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:open-emr:openemr:*:*:*:*:*:*:*:*
vendors:
  - OpenEMR
products:
  - OpenEMR (7.0.1 - 8.3.x)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550.002
    technique_name: Pass the Hash
    evidence: Attackers holding a captured token can replay it or brute-force the PIN to open patient-portal sessions
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110.001
    technique_name: Password Guessing
    evidence: checks login_pin without rate limiting or strict comparison
    confidence_band: high
cves:
  - id: CVE-2026-124445
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124445
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade OpenEMR to 8.4.0 or later to patch CVE-2026-124445
      owner: IT Operations
      due: 24h
      evidence: Vulnerability is remediated in version 8.4.0
  hunt_leads:
    - lead: Identify high-frequency POST requests to patient portal authentication endpoints
      technique_id: T1110.001
      data_needed:
        - Web server access logs (cs-method, cs-uri-stem, sc-status)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The lack of rate limiting on login_pin allows brute-force attacks
---

OpenEMR versions from 7.0.1 up to 8.4.0 contain a critical flaw in the `src/Common/Auth/OneTimeAuth.php` component. The application fails to properly respect `enforce_onetime_use` and `max_access_count` flags, resulting in service_auth tokens remaining active after use. Additionally, the `login_pin` verification process lacks rate limiting and strict comparison, allowing attackers to perform brute-force attacks against the PIN. 

## Impact
Successful exploitation allows unauthenticated attackers to hijack patient portal sessions by replaying captured tokens or brute-forcing PINs. This results in the unauthorized disclosure of sensitive Protected Health Information (PHI).

## Recommendation
- Upgrade OpenEMR to version 8.4.0 or later immediately.
- Review web server access logs for anomalous, high-frequency requests directed at the authentication endpoints handled by `OneTimeAuth.php` to identify potential brute-force attempts.
- Audit existing authentication tokens and session logs for evidence of token reuse.
