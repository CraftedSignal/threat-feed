---
brief_id: brief-2026-11-11-wwbn-avideo-auth-bypass
event_id: brief-2026-11-11-wwbn-avideo-auth-bypass
revision: 1
activity_at: "2026-11-11T02:09:05Z"
title: 'WWBN AVideo: Authentication bypass via Hybridauth social login (CVE-2026-126542)'
slug: 2026-11-wwbn-avideo-auth-bypass
description: WWBN AVideo versions 6.5 through 29.7.1 contain an authentication bypass vulnerability allowing unauthenticated attackers to impersonate any user, including administrators, by manipulating social login display names.
date: "2026-11-11T02:09:05Z"
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
  validation_status: Needs environment validation of web server access logs for OAuth endpoints
cpes:
  - cpe:2.3:a:wwbn:avideo:*:*:*:*:*:*:*:*
vendors:
  - WWBN
products:
  - AVideo (6.5 - 29.7.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550.001
    technique_name: Application Access Token
    subtechnique_id: T1550.001
    subtechnique_name: Application Access Token
    evidence: Attackers can set their X, Facebook, Yahoo or LinkedIn display name to a victim's username and withhold email, causing login.json.php or oauth2.php to log them in as that account.
    confidence_band: high
cves:
  - id: CVE-2026-126542
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-126542
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade AVideo to a version later than 29.7.1
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects versions 6.5 through 29.7.1
  hunt_leads:
    - lead: Inspect web server access logs for repeated requests to login.json.php or oauth2.php followed by successful administrative sessions.
      technique_id: T1550.001
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit targets login.json.php or oauth2.php endpoints to authenticate without password.
  mitigation_plan:
    - priority: immediate
      action: Disable social login (OAuth/Hybridauth) integrations
      owner: IT Operations
      addresses: CVE-2026-126542
      evidence: Vulnerability is inherent to the Hybridauth social login implementation
---

WWBN AVideo contains an authentication bypass vulnerability in its implementation of the Hybridauth library. An attacker can exploit this by setting their display name on supported social platforms (X, Facebook, Yahoo, or LinkedIn) to match an existing victim's username on the target AVideo instance. By withholding the email address during the OAuth flow, the application incorrectly trusts the social display name, allowing the attacker to authenticate as the target user, including accounts with administrative privileges, without requiring a password.

## Impact

Unauthenticated attackers can achieve full account takeover of any user on the platform. If an administrator's username is known, the attacker can gain full administrative access to the AVideo instance.

## Recommendation

- Immediately update AVideo to a version beyond 29.7.1 that includes the security fix for Hybridauth integration.
- Review authentication logs for suspicious logins, specifically identifying successful logins originating from OAuth endpoints (`login.json.php` or `oauth2.php`) that show unusual patterns or unexpected user account associations.
- Temporarily disable social login functionality if an immediate update cannot be performed.
