---
brief_id: brief-2026-10-22-jetbrains-youtrack-auth-bypass
event_id: brief-2026-10-22-jetbrains-youtrack-auth-bypass
revision: 1
activity_at: "2026-10-22T00:38:15Z"
title: 'JetBrains YouTrack: Helpdesk authentication bypass via account merging (CVE-2026-86478)'
slug: 2026-10-jetbrains-youtrack-auth-bypass
description: An authentication bypass vulnerability in JetBrains YouTrack Helpdesk allows unauthenticated attackers to hijack any user account, including administrators, by spoofing emails to trigger an insecure account merging process.
date: "2026-10-22T00:38:15Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - LHeiakim
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Needs internal environment check.
cpes:
  - cpe:2.3:a:jetbrains:youtrack:*:*:*:*:*:*:*:*
tags:
  - jetbrains
  - authentication-bypass
  - cve
  - account-takeover
vendors:
  - JetBrains
products:
  - YouTrack (< 2025.3.161254, < 2026.1.14042)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can create a reporter account, change the associated email address to that of a legitimate target, and trigger a merge process.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The system generates and returns a Hub interactive login URL associated with the merged (victim) account.
    confidence_band: high
cves:
  - id: CVE-2026-86478
    cvss: 9.8
    epss: 0.00606
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86478
  - https://www.jetbrains.com/privacy-security/issues-fixed/
  - https://sploitus.com/exploit?id=99C6972E-C2A1-5ED0-94AF-A163B9AB855B
  - https://sploitus.com/exploit?id=99C6972E-C2A1-5ED0-94AF-A163B9AB855B&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-86478 Exploitation - Suspicious Reporter Landing and Merge
    description: Detects potential exploitation attempts of CVE-2026-86478 by identifying POST requests to the reporter landing endpoint followed by account merge operations.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1552
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch YouTrack installations to versions 2025.3.161254 or 2026.1.14042.
      owner: IT Operations
      due: 24h
      evidence: JetBrains official fix advisory.
  hunt_leads:
    - lead: Search logs for /api/reporterLanding activity
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source indicates this endpoint is the entry point for account merging.
  mitigation_plan:
    - priority: immediate
      action: Restrict or disable Helpdesk feature for public-facing YouTrack instances.
      owner: IT Operations
      addresses: CVE-2026-86478
      evidence: Recommended mitigation in source.
---

JetBrains YouTrack Helpdesk contains a critical authentication bypass vulnerability (CVE-2026-86478) originating from improper validation in the reporter account merging logic. The flaw allows an unauthenticated user to associate their reporter account with the email address of a legitimate target. Because the application fails to verify the reporter type or account ownership during the merge process, the attacker can force the system to merge their account into the target account, resulting in the generation of an interactive login URL that grants full access to the victim's session.

## Attack Chain

1. An attacker submits a public Helpdesk form using their own email address to trigger account creation as an unverified REPORTER.
2. The attacker receives a confirmation email containing a magic-link signed token (valid for 14 days).
3. The attacker opens the magic-link to establish a browser session as the reporter.
4. The attacker navigates to their profile and modifies the associated email address to match that of the target user (e.g., an administrator).
5. The attacker opens the original magic-link again.
6. The `onReporterEmailVerified` function processes the session, detects the shared email, and executes an insecure merge into the target account.
7. The system generates and returns a Hub interactive login URL associated with the merged (victim) account.
8. The attacker navigates to the returned login URL to obtain an active, authenticated session as the victim.

## Impact

The vulnerability allows full unauthorized access to any user account within the affected YouTrack instance, including accounts with administrative privileges, leading to complete instance compromise.

## Recommendation

- Patch YouTrack immediately: Upgrade to version 2025.3.161254 or 2026.1.14042 or later.
- Mitigate until patched: Disable the Helpdesk feature or restrict account self-service profile updates.
- Review Audit Logs: Monitor for unexpected "Merging reporters with email" events and excessive use of `POST /api/reporterLanding` endpoints from unknown or unverified reporter sessions.
- Proactive Hardening: Rotate tokens and credentials for administrative accounts if a compromise is suspected.
