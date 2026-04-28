---
title: OpenClaw Incorrect Authorization Vulnerability (CVE-2026-35653)
slug: 2026-04-openclaw-auth-bypass
description: OpenClaw before 2026.3.24 contains an incorrect authorization vulnerability in the POST /reset-profile endpoint, allowing authenticated callers with operator.write access to browser.request to bypass profile mutation restrictions and escalate privileges.
date: "2026-04-11T12:00:00Z"
severities:
  - high
tags:
  - vulnerability
  - authorization bypass
  - privilege escalation
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
cves:
  - id: CVE-2026-35653
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35653
  - https://github.com/openclaw/openclaw/commit/4dcc39c25c6cc63fedfd004f52d173716576fcf0
  - https://github.com/openclaw/openclaw/commit/e7d11f6c33e223a0dd8a21cfe01076bd76cef87a
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-xp9r-prpg-373r
  - https://www.vulncheck.com/advisories/openclaw-incorrect-authorization-in-post-reset-profile-via-browser-request
rules:
  - title: Detect OpenClaw Profile Reset Attempt
    description: Detects POST requests to the /reset-profile endpoint, potentially indicating an attempted exploitation of CVE-2026-35653.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1548
      - T1548.001
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Profile Directory Manipulation
    description: Detects file operations indicative of unauthorized profile directory manipulation in OpenClaw.
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - file_event
      - linux
rules_count: 2
---

OpenClaw, a software application of unknown purpose, is susceptible to an incorrect authorization vulnerability tracked as CVE-2026-35653. This flaw affects versions prior to 2026.3.24. The vulnerability lies within the `/reset-profile` endpoint, specifically when accessed via a POST request. An authenticated user with `operator.write` access combined with `browser.request` permissions can exploit this to bypass intended profile mutation restrictions. This bypass allows the attacker to perform administrative actions beyond their privilege level, leading to potential disruption of service and data alteration. This issue was reported and patched in version 2026.3.24 of OpenClaw.

## Attack Chain

1. An attacker authenticates to OpenClaw with a user account that possesses both `operator.write` and `browser.request` permissions.
2. The attacker crafts a POST request targeting the `/reset-profile` endpoint.
3. The attacker bypasses authorization checks due to the incorrect implementation.
4. The attacker leverages the bypassed authorization to send commands to stop the running browser instance controlled by OpenClaw.
5. The attacker proceeds to close Playwright connections managed by the application.
6. The attacker moves profile directories associated with OpenClaw to the Trash, potentially deleting or corrupting user data.
7. The attacker gains unauthorized control over browser instances and profile management functions.
8. The ultimate goal is to disrupt the OpenClaw service and potentially compromise or delete user profiles.

## Impact

Successful exploitation of this vulnerability could lead to denial of service, data loss, and unauthorized modification of user profiles. While the exact number of affected organizations is unknown, any deployment of OpenClaw prior to version 2026.3.24 is vulnerable. If successfully exploited, an attacker can cause significant disruption by terminating browser instances and deleting associated profile data. The CVSS v3.1 score of 8.1 indicates a high potential for impact, particularly in environments where OpenClaw is critical for business operations.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.24 or later to remediate the vulnerability (CVE-2026-35653).
*   Monitor web server logs for POST requests to the `/reset-profile` endpoint originating from users with both `operator.write` and `browser.request` privileges, as these may indicate exploitation attempts. Use the rule "Detect OpenClaw Profile Reset Attempt" to detect this activity.
*   Implement strict access controls to limit the number of users with `operator.write` and `browser.request` privileges to minimize the attack surface.
*   Deploy the Sigma rule "Detect OpenClaw Profile Directory Manipulation" to identify suspicious file operations that could indicate unauthorized profile manipulation.
