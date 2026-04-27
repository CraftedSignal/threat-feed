---
title: Chamilo LMS Session Fixation Vulnerability (CVE-2026-31940)
slug: 2026-04-chamilo-session-fixation
description: Chamilo LMS versions prior to 1.11.38 and 2.0.0-RC.3 are vulnerable to session fixation due to user-controlled request parameters being used to set the PHP session ID, potentially allowing attackers to hijack user sessions.
date: "2026-04-11T14:30:00Z"
severities:
  - medium
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

Chamilo LMS, a learning management system, is susceptible to a session fixation vulnerability (CVE-2026-31940) in versions prior to 1.11.38 and 2.0.0-RC.3. The vulnerability stems from the application's handling of user-controlled request parameters in the `main/lp/aicc_hacp.php` file. Specifically, these parameters are used directly to set the PHP session ID before the global bootstrap is loaded. This allows an attacker to potentially set a predictable session ID for a user, leading to session…
