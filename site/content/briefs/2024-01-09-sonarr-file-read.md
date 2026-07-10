---
title: Unauthenticated Remote File Read Vulnerability in Sonarr (CVE-2026-30976)
slug: 2024-01-09-sonarr-file-read
description: CVE-2026-30976 allows an unauthenticated remote attacker to read arbitrary files readable by the Sonarr process on Windows systems running vulnerable versions prior to 4.0.17.2950, potentially exposing sensitive data.
date: "2024-01-09T16:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - CVE-2026-30976
  - sonarr
  - file-read
  - windows
vendors:
  - Sonarr
products:
  - Sonarr
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-30976
rules:
  - title: Sonarr CVE-2026-30976 File Read Attempt
    description: Detects attempts to exploit CVE-2026-30976 by looking for suspicious file path traversal patterns in HTTP requests to the Sonarr server.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - windows
  - title: Sonarr Configuration File Access Attempt
    description: Detects attempts to access configuration files via the Sonarr web interface, potentially indicating CVE-2026-30976 exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - windows
rules_count: 2
---

CVE-2026-30976 is a critical unauthenticated remote file read vulnerability affecting Sonarr, a PVR for Usenet and BitTorrent users. This vulnerability exists in the 4.x branch of Sonarr prior to version 4.0.17.2950. An unauthenticated attacker can exploit this flaw to read any file accessible by the Sonarr process, including sensitive application configuration files containing API keys and database credentials, as well as Windows system files and user-accessible data. This vulnerability is specific to Windows installations of Sonarr; macOS and Linux systems are not affected. The issue stems from insufficient validation of file paths, allowing attackers to traverse directories and access unauthorized files. The vulnerability has been patched in version 4.0.17.2950 (nightly/develop branch) and 4.0.17.2952 (stable/main releases).

## Attack Chain

1.  The attacker identifies a vulnerable Sonarr instance running on a Windows system.
2.  The attacker sends a crafted HTTP request to the Sonarr server, exploiting the file path traversal vulnerability. The request targets a specific file, such as `C:\\Windows\\win.ini`.
3.  Sonarr processes the malicious HTTP request without proper validation of the file path.
4.  The Sonarr process reads the contents of the requested file (e.g., `C:\\Windows\\win.ini`).
5.  The file contents are returned to the attacker in the HTTP response body.
6.  The attacker can then retrieve sensitive information such as API keys, database credentials from configuration files, or even access operating system files.
7.  The attacker uses the extracted API keys or database credentials for further malicious activities, such as unauthorized access to connected services or data exfiltration.

## Impact

Successful exploitation of CVE-2026-30976 can lead to complete compromise of the Sonarr instance and potentially the underlying Windows system. An attacker could gain access to sensitive API keys, database credentials, and other confidential information, enabling them to perform unauthorized actions or steal valuable data. Given that Sonarr is often used to manage media libraries, the vulnerability could also expose users' personal files. The number of affected Sonarr installations is unknown, but the impact is high due to the sensitive nature of the exposed data.

## Recommendation

*   Upgrade Sonarr to version 4.0.17.2950 (nightly/develop) or 4.0.17.2952 (stable/main) to patch CVE-2026-30976.
*   Enable logging for the webserver component of Sonarr and deploy the Sigma rule `Sonarr CVE-2026-30976 File Read Attempt` to detect exploitation attempts.
*   If immediate patching is not possible, restrict access to the Sonarr web interface to a secure internal network and use a VPN or similar solution for external access as a workaround.
*   Monitor network traffic for suspicious outbound connections originating from the Sonarr server that might indicate unauthorized data exfiltration.
