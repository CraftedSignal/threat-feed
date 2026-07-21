---
title: Home Assistant Core Path Traversal Vulnerability (CVE-2026-64825)
slug: 2026-07-home-assistant-pathtraversal
description: A critical path traversal vulnerability, CVE-2026-64825, in Home Assistant Core versions before 2026.6.0 allows unauthenticated attackers to write arbitrary files to any directory on the host filesystem by uploading a crafted backup archive during the initial onboarding window, potentially leading to full system compromise with root privileges.
date: "2026-07-21T16:30:46Z"
lastmod: "2026-07-21T16:31:40Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - path-traversal
  - home-assistant
  - rce
  - unauthenticated
  - initial-access
vendors:
  - Home Assistant
products:
  - Home Assistant Core < 2026.6.0
affected_os:
  - linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: allows unauthenticated attackers to write arbitrary files to any directory on the host filesystem by uploading a crafted backup archive during the initial onboarding window.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: full filesystem access when the process runs as root.
    confidence_band: high
cves:
  - id: CVE-2026-64825
    cvss: 9.3
  - id: CVE-2026-64824
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-64825
  - https://nvd.nist.gov/vuln/detail/CVE-2026-64824
updates:
  - at: "2026-07-21T16:31:40Z"
    level: L2
    summary: added CVE-2026-64824
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-64824
---

A critical path traversal vulnerability, identified as CVE-2026-64825, affects Home Assistant Core versions prior to 2026.6.0. This flaw allows unauthenticated attackers to write arbitrary files to any directory on the host filesystem during the initial onboarding process. Attackers exploit this by uploading a specially crafted backup archive. Within this archive, the `backup.json` file's 'name' field is modified to include an absolute path. The vulnerability lies in how Home Assistant handles this path with `pathlib.Path.__truediv__`, causing the intended backup directory prefix to be ignored. This allows attacker-controlled content to be placed at arbitrary locations, potentially leading to full filesystem compromise. If the Home Assistant process operates with root privileges, this can escalate to full system control. The vulnerability's high CVSS v3.1 base score of 9.3 underscores its severe impact, enabling unauthenticated remote attackers to gain significant control over affected systems.

## Attack Chain

1. An unauthenticated attacker identifies a Home Assistant Core instance that is undergoing its initial onboarding configuration.
2. The attacker crafts a malicious backup archive, ensuring it contains a specially modified `backup.json` file.
3. Inside the `backup.json` file, the 'name' field is manipulated to specify an absolute path on the target filesystem (e.g., `/etc/passwd` or a web server root for remote code execution).
4. The attacker uploads this specially crafted backup archive through the Home Assistant onboarding web interface, leveraging the legitimate backup restore functionality.
5. Home Assistant Core begins processing the uploaded archive, parsing the `backup.json` file.
6. Due to the path traversal vulnerability in `pathlib.Path.__truediv__`, the application discards the expected backup directory prefix and interprets the 'name' field's absolute path directly.
7. The attacker-controlled content from the backup archive is then written to the arbitrary absolute path specified, leading to an unauthenticated arbitrary file write.
8. If the Home Assistant process is running with root privileges, this arbitrary file write can be leveraged for privilege escalation or remote code execution, resulting in full system compromise.

## Impact

Successful exploitation of CVE-2026-64825 results in unauthenticated arbitrary file write capabilities on the host filesystem. This critical vulnerability allows attackers to place malicious files, such as web shells, startup scripts, or configuration files, in sensitive system directories. If the Home Assistant process is running with elevated privileges, typically root on Linux systems, attackers can achieve privilege escalation, leading to full system compromise. The potential impact includes remote code execution, unauthorized data access, system alteration, and the establishment of persistent backdoors. While specific victim numbers are not provided, all unpatched Home Assistant Core instances exposed during their initial onboarding window are at risk of complete takeover.

## Recommendation

* Patch CVE-2026-64825 immediately by upgrading all Home Assistant Core instances to version 2026.6.0 or later.
* Ensure Home Assistant instances are not publicly exposed during the initial onboarding window, as this is the primary vector for exploitation of this vulnerability.
* Monitor `webserver` logs for suspicious POST requests to backup or onboarding related endpoints, especially if an anomalous number of such requests occur or if requests contain unusual file sizes/types for backup archives.
* Implement endpoint detection and response (EDR) solutions to monitor for unexpected file creations or modifications by the Home Assistant process (`file_event`, `process_creation` log sources) in sensitive system directories (e.g., `/etc/`, web root directories), which would indicate post-exploitation activity.
