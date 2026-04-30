---
title: Chamilo LMS Session Fixation Vulnerability (CVE-2026-31940)
slug: 2026-04-chamilo-session-fixation
description: Chamilo LMS versions prior to 1.11.38 and 2.0.0-RC.3 are vulnerable to session fixation due to user-controlled request parameters being used to set the PHP session ID, potentially allowing attackers to hijack user sessions.
date: "2026-04-11T14:30:00Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - session-fixation
  - web-application
  - cve-2026-31940
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-31940
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-31940
  - https://github.com/chamilo/chamilo-lms/commit/ce0192c62e48c9d9474d915c541b3274844afbf9
  - https://github.com/chamilo/chamilo-lms/commit/e337b7cc74a0276a0b4f91f9282204d20cac1869
  - https://github.com/chamilo/chamilo-lms/security/advisories/GHSA-4gp7-cfjh-77gv
rules:
  - title: Detect Access to aicc_hacp.php
    description: Detects access to the vulnerable aicc_hacp.php script which is susceptible to session fixation
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Potentially Malicious Session ID Parameter
    description: Detects requests that may be attempting to set a specific session ID via a request parameter in aicc_hacp.php.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Chamilo LMS, a learning management system, is susceptible to a session fixation vulnerability (CVE-2026-31940) in versions prior to 1.11.38 and 2.0.0-RC.3. The vulnerability stems from the application's handling of user-controlled request parameters in the `main/lp/aicc_hacp.php` file. Specifically, these parameters are used directly to set the PHP session ID before the global bootstrap is loaded. This allows an attacker to potentially set a predictable session ID for a user, leading to session hijacking. The vulnerability was reported and patched, with fixes available in versions 1.11.38 and 2.0.0-RC.3. This is important for defenders to address to ensure integrity and confidentiality of user sessions.

## Attack Chain

1.  Attacker crafts a malicious URL or form containing a specific session ID.
2.  Attacker lures a victim to access the crafted URL or form.
3.  The victim's browser sends a request to the Chamilo LMS server with the attacker-controlled session ID.
4.  The Chamilo LMS application, specifically the `main/lp/aicc_hacp.php` script, uses the attacker-provided session ID to initialize the PHP session.
5.  The victim authenticates to the Chamilo LMS application.
6.  The attacker uses the predetermined session ID to access the victim's authenticated session.
7.  Attacker gains unauthorized access to the victim's account and associated data within the Chamilo LMS.

## Impact

Successful exploitation of this vulnerability allows an attacker to hijack legitimate user sessions on a Chamilo LMS instance. This could result in unauthorized access to sensitive student or instructor data, modification of course content, or other malicious activities. The impact is high, particularly for educational institutions and organizations that rely on Chamilo LMS for their online learning platforms.

## Recommendation

*   Upgrade Chamilo LMS to version 1.11.38 or 2.0.0-RC.3 or later to patch CVE-2026-31940.
*   Monitor web server logs for suspicious requests to `main/lp/aicc_hacp.php` containing unusual session ID parameters. Use the provided Sigma rule to detect potential exploitation attempts.
*   Implement the "Detect Potentially Malicious Session ID Parameter" Sigma rule to identify exploitation attempts.
