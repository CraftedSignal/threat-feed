---
title: Rclone Unauthenticated Remote Code Execution Vulnerabilities
slug: 2026-04-rclone-rce
description: Rclone versions prior to 1.73.5 are vulnerable to two critical unauthenticated remote code execution vulnerabilities (CVE-2026-41176 and CVE-2026-41179) when the remote control API is enabled without authentication, potentially allowing attackers to execute arbitrary commands and compromise the system.
date: "2026-04-25T12:00:00Z"
severities:
  - critical
exploited: true
tags:
  - vulnerability
  - rce
  - cloud
vendors:
  - Rclone
products:
  - Rclone
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
cves:
  - id: CVE-2026-41176
    epss: 0.02794
  - id: CVE-2026-41179
    epss: 0.05976
references:
  - https://ccb.belgium.be/advisories/warning-two-critical-unauthenticated-code-execution-vulnerabilities-rclone-patch
  - https://github.com/rclone/rclone/security/advisories/GHSA-25qr-6mpr-f7qx
  - https://github.com/rclone/rclone/security/advisories/GHSA-jfwf-28xr-xw6q
  - https://feedly.com/cve/CVE-2026-41176
  - https://feedly.com/cve/CVE-2026-41179
rules:
  - title: Detect Rclone RC API Access Without Authentication
    description: Detects access to the Rclone RC API without HTTP authentication, indicating a potential vulnerability (CVE-2026-41176, CVE-2026-41179).
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Rclone WebDAV RC Exploit Attempt (CVE-2026-41179)
    description: Detects suspicious requests to the Rclone RC API that may indicate an attempt to exploit the WebDAV command execution vulnerability (CVE-2026-41179).
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1210
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Two critical unauthenticated remote code execution vulnerabilities, CVE-2026-41176 and CVE-2026-41179, have been discovered in Rclone versions prior to 1.73.5. Rclone is a command-line program used to manage files on cloud storage services. These vulnerabilities can be exploited if the Rclone remote control (RC) API is enabled without proper authentication (e.g., `--rc-user/--rc-pass/--rc-htpasswd`). An attacker with network access to a vulnerable Rclone instance can bypass authentication…
