---
title: CVE-2026-16310 Unauthenticated Password Reset in MemberDash
slug: 2026-09-memberdash-idor
description: The MemberDash WordPress plugin contains an IDOR vulnerability allowing unauthenticated attackers to perform unauthorized password resets for arbitrary users via the registration registration process.
date: "2026-09-06T03:35:40Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:memberdash:memberdash:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - wordpress
  - idor
  - account-takeover
vendors:
  - MemberDash
products:
  - MemberDash (<= 1.8.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can exploit the 'id' parameter in the registration process to perform unauthorized password resets.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: This makes it possible for unauthenticated attackers to change the password of any WordPress user.
    confidence_band: high
cves:
  - id: CVE-2026-16310
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16310
rules:
  - title: Detects CVE-2026-16310 Exploitation - Unauthenticated Password Reset Attempt
    description: Detects attempts to exploit CVE-2026-16310 by monitoring POST requests to MemberDash registration endpoints containing an 'id' parameter.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Update MemberDash plugin to version > 1.8.5
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable in all versions up to 1.8.5
  hunt_leads:
    - lead: Search logs for unusual POST requests to registration endpoints with high-value ID parameters (e.g., id=1)
      technique_id: T1190
      data_needed:
        - webserver_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers supply an arbitrary user ID during registration
  mitigation_plan:
    - priority: immediate
      action: Upgrade MemberDash plugin
      owner: IT Operations
      addresses: CVE-2026-16310
      evidence: Vulnerability fixed in releases following 1.8.5
---

The MemberDash plugin for WordPress, in all versions up to and including 1.8.5, is susceptible to an Insecure Direct Object Reference (IDOR) vulnerability. The flaw exists due to inadequate validation of a user-controlled 'id' parameter during the registration process. This oversight allows unauthenticated attackers to supply an arbitrary user ID, enabling them to reset the password of any existing WordPress user, including those with administrative privileges. This exploit facilitates silent account takeover, as the system does not notify the victim of the credential change. Given the critical severity (CVSS 9.8) and the high impact of total administrative compromise on WordPress environments, immediate patching is required.

## Impact

Successful exploitation of this vulnerability leads to total account takeover of any WordPress user account. Attackers targeting administrative accounts gain full control over the WordPress installation, allowing for malicious plugin installation, sensitive data exfiltration, and secondary persistent access within the targeted environment.

## Recommendation

- Upgrade the MemberDash plugin to a version beyond 1.8.5 immediately.
- Audit WordPress user accounts and administrative logs for unauthorized password reset events or suspicious account registration patterns.
- Implement strict rate limiting on registration endpoints to mitigate automated exploitation attempts.
