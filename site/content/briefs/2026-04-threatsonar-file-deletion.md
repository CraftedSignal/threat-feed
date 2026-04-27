---
title: ThreatSonar Anti-Ransomware Arbitrary File Deletion Vulnerability
slug: 2026-04-threatsonar-file-deletion
description: TeamT5's ThreatSonar Anti-Ransomware is vulnerable to arbitrary file deletion via path traversal, allowing authenticated remote attackers with web access to delete arbitrary files on the system.
date: "2026-04-20T08:16:11Z"
severities:
  - high
tags:
  - vulnerability
  - file-deletion
  - path-traversal
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-5966
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5966
  - https://www.twcert.org.tw/en/cp-139-10832-05f3a-2.html
  - https://www.twcert.org.tw/tw/cp-132-10831-a734d-1.html
rules:
  - title: Detect Path Traversal Attempts in Web Server Logs
    description: Detects path traversal attempts in web server logs based on common directory traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - windows|linux
  - title: Detect HTTP 403 with Path Traversal Attempts
    description: Detects HTTP 403 errors associated with path traversal attempts, indicating a blocked attack.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - windows|linux
rules_count: 2
---

CVE-2026-5966 describes an arbitrary file deletion vulnerability in TeamT5's ThreatSonar Anti-Ransomware. The vulnerability allows authenticated remote attackers with web access to exploit a path traversal flaw. This means that an attacker who already has valid credentials to access the web interface of ThreatSonar Anti-Ransomware can craft malicious requests to delete files that the application user has access to, regardless of their intended purpose or location. The CVSS v3.1 score is 8.1…
