---
title: ZoneMinder Authenticated OS Command Injection via Monitor Name
slug: 2026-10-zoneminder-rce
description: An authenticated OS command injection vulnerability (CVE-2026-102608) in ZoneMinder versions prior to 1.38.3 allows remote code execution via unsanitized monitor names during event export operations.
date: "2026-10-16T20:44:29Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:zoneminder:zoneminder:*:*:*:*:*:*:*:*
tags:
  - command-injection
  - vulnerability
  - remote-code-execution
  - surveillance
vendors:
  - ZoneMinder
products:
  - ZoneMinder (< 1.38.3)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: In this attack mechanism, the stored monitor Name reaches both the ffmpeg concatenation command and the tar or zip archive command and breaks out of manual quoting.
    confidence_band: high
cves:
  - id: CVE-2026-102608
    cvss: 9
references:
  - https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-88m4-hrgp-m9v3
  - https://github.com/ZoneMinder/zoneminder/releases/tag/1.38.3
  - https://sploitus.com/exploit?id=CVELIST:CVE-2026-102608
rules:
  - title: Detects CVE-2026-102608 Exploitation - Malicious Monitor Name Injection
    description: Detects exploitation attempts against CVE-2026-102608 by monitoring for shell metacharacters in HTTP requests to the event download functionality.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade ZoneMinder to version 1.38.3 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-102608 vulnerability patch release
  hunt_leads:
    - lead: Search for shell metacharacters in Monitor Name database fields
      technique_id: T1059
      data_needed:
        - Database logs or direct SQL inspection of the Monitors table
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows persistent command injection via the Monitor Name field
  mitigation_plan:
    - priority: immediate
      action: Upgrade to ZoneMinder 1.38.3
      owner: IT Operations
      addresses: CVE-2026-102608
      evidence: Vendor security advisory and release notes
---

ZoneMinder, an open-source closed-circuit television (CCTV) software, contains a critical OS command injection vulnerability tracked as CVE-2026-102608. The issue stems from the improper sanitization of the 'Monitor Name' field within the `download_functions.php` script. Specifically, the application uses manual single-quote wrapping instead of robust functions like `escapeshellarg()` when constructing command-line arguments for system utilities including `ffmpeg`, `tar`, and `zip`. 

An attacker possessing monitor-create or monitor-edit permissions can inject shell metacharacters into a monitor name. When a user with 'Events View' permissions triggers an event export for that monitor, the malicious input breaks out of the manual quoting, leading to arbitrary command execution in the context of the web server user. This vulnerability is fixed in version 1.38.3. Given the public availability of proof-of-concept exploit code, immediate patching is required for all instances.

## Attack Chain

1. The attacker gains initial access to the ZoneMinder web interface with credentials possessing monitor-create or monitor-edit privileges.
2. The attacker navigates to the monitor configuration and creates or renames a monitor, inserting shell metacharacters (e.g., `;`, `&&`, `$()`) into the 'Monitor Name' field.
3. The malicious monitor name is saved into the backend database.
4. An authenticated user with 'Events View' permissions initiates an event export process for the compromised monitor.
5. The `download_functions.php` script retrieves the monitor name from the database.
6. The script improperly concatenates the name into shell commands for `ffmpeg`, `tar`, or `zip` utilities.
7. The system executes the injected commands as the web server user process (e.g., www-data).
8. Final objective achieved: remote command execution, potential lateral movement, or system compromise.

## Impact

Successful exploitation allows for full remote code execution on the underlying server as the web server user. This provides the attacker the ability to pivot deeper into the internal network, exfiltrate stored CCTV footage, or disrupt surveillance operations. This vulnerability is rated with a CVSS 9.0 (High) score, posing a significant risk to organizations relying on ZoneMinder for physical security monitoring.

## Recommendation

* Upgrade ZoneMinder to version 1.38.3 or later immediately to patch CVE-2026-102608.
* Audit existing monitor names for the presence of shell metacharacters such as semicolon, pipe, or backticks using the web interface or direct database queries.
* Review web server access logs for anomalous requests to `download_functions.php` that include excessive query parameters or shell metacharacters.
* Enforce strict role-based access control (RBAC) to limit the number of users with monitor-create or monitor-edit permissions.
