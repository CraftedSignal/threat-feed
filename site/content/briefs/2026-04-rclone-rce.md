---
title: Rclone Unauthenticated Remote Code Execution Vulnerabilities
slug: 2026-04-rclone-rce
description: Rclone versions prior to 1.73.5 are vulnerable to two critical unauthenticated remote code execution vulnerabilities (CVE-2026-41176 and CVE-2026-41179) when the remote control API is enabled without authentication, potentially allowing attackers to execute arbitrary commands and compromise the system.
date: "2026-04-25T12:00:00Z"
type: threat
types:
  - threat
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
    epss: 0.063
  - id: CVE-2026-41179
    epss: 0.09603
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

Two critical unauthenticated remote code execution vulnerabilities, CVE-2026-41176 and CVE-2026-41179, have been discovered in Rclone versions prior to 1.73.5. Rclone is a command-line program used to manage files on cloud storage services. These vulnerabilities can be exploited if the Rclone remote control (RC) API is enabled without proper authentication (e.g., `--rc-user/--rc-pass/--rc-htpasswd`). An attacker with network access to a vulnerable Rclone instance can bypass authentication, execute arbitrary commands, and potentially gain full system compromise. As organizations increasingly rely on cloud storage, vulnerabilities in tools like Rclone can have significant impact by enabling data theft and lateral movement. The vulnerabilities were reported on April 24, 2026, with no known active exploitation as of April 23, 2026.

## Attack Chain

1. The attacker identifies a target system running Rclone with the RC API enabled.
2. The attacker verifies the RC API is exposed on a reachable network address (e.g., not only localhost) and is not protected by HTTP authentication.
3. For CVE-2026-41179, the attacker sends a single crafted HTTP request to the RC endpoint, leveraging the WebDAV backend initialization process.
4. This crafted request triggers the execution of arbitrary commands on the target system without authentication.
5. For CVE-2026-41176, the attacker bypasses authentication controls to access sensitive administrative functionality.
6. The attacker manipulates Rclone configuration or invokes operational RC methods to execute arbitrary commands.
7. The attacker gains local file read/write access, potentially stealing sensitive data or uploading malicious payloads.
8. The attacker achieves full system compromise, enabling data theft, lateral movement within the network, or denial of service.

## Impact

Successful exploitation of CVE-2026-41176 and CVE-2026-41179 can lead to full system compromise, data theft, lateral movement, or denial of service. Specifically, attackers can achieve local file read, file write, or shell access, depending on the environment. The impact includes potential exposure of sensitive cloud data and configurations, which could compromise the integrity and confidentiality of stored information. Given Rclone's popularity among organizations managing cloud storage, a successful attack could affect a large number of victims across various sectors.

## Recommendation

*   Upgrade Rclone to version 1.73.5 or later to patch CVE-2026-41176 and CVE-2026-41179 as recommended by the vendor.
*   Enable global HTTP authentication on RC servers using `--rc-user`, `--rc-pass`, or `--rc-htpasswd` to mitigate the unauthenticated access, as mentioned in the description of the vulnerabilities.
*   Implement network-level controls (e.g., firewall rules) to restrict access to RC server endpoints and the RC service, as suggested by CCB.
*   Deploy the Sigma rule "Detect Rclone RC API Access Without Authentication" to identify potentially vulnerable Rclone instances within your environment.
