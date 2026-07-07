---
title: Splunk RCE Through Arbitrary File Write to Windows System Root
slug: 2026-07-splunk-rce-arbitrary-file-write
description: A critical vulnerability (CVE-2024-45731, CVE-2024-45733) in Splunk Enterprise for Windows versions below 9.3.0, 9.2.3, and 9.1.6 allows low-privileged users to perform arbitrary file writes to the Windows system root directory (C:\Windows\System32) when Splunk is installed on a separate drive, enabling remote code execution through insecure session storage configuration.
date: "2026-07-03T13:38:10Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:splunk:splunk:*:*:*:*:enterprise:*:*:*
  - cpe:2.3:a:splunk:splunk:9.3.0:*:*:*:enterprise:*:*:*
tags:
  - application-vulnerability
  - rce
  - file-write
  - privilege-escalation
  - splunk
  - windows
vendors:
  - Splunk
products:
  - Splunk Enterprise for Windows (versions < 9.3.0)
  - Splunk Enterprise for Windows (versions < 9.2.3)
  - Splunk Enterprise for Windows (versions < 9.1.6)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: a low-privileged user ... could write a file to the Windows system root directory ... Additionally, this user may be able to upload and execute code due to insecure session storage configuration.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: a low-privileged user that does not hold the 'admin' or 'power' Splunk roles could write a file to the Windows system root directory ... which has a default location of C:\Windows\System32
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: this user may be able to upload and execute code due to insecure session storage configuration.
    confidence_band: high
cves:
  - id: CVE-2024-45731
    cvss: 8
    epss: 0.00535
  - id: CVE-2024-45733
    cvss: 8.8
    epss: 0.01092
references:
  - https://advisory.splunk.com/advisories/SVD-2024-1001
  - https://advisory.splunk.com/advisories/SVD-2024-1003
rules:
  - title: Detect CVE-2024-45731/CVE-2024-45733 Exploitation Attempt - Splunk Vulnerable Endpoint Access
    description: Detects attempts to exploit CVE-2024-45731 and CVE-2024-45733 by accessing the Splunk API endpoint /search/apps/local/_new, which can lead to arbitrary file write and RCE. This rule monitors Splunk's internal access logs (`splunkd_access`).
    platform: sigma
    severity: high
    tactics:
      - exploitation
    techniques:
      - T1210
    data_sources:
      - application
      - splunk
      - splunkd_access
  - title: Detect CVE-2024-45731/CVE-2024-45733 Exploitation - Splunk Low-Privilege App Creation Error
    description: Detects errors indicating a low-privileged Splunk user attempted to create an app or perform related actions requiring elevated capabilities (edit_local_apps or admin_all_objects). This can be a sign of attempted exploitation of the arbitrary file write vulnerability (CVE-2024-45731) and RCE (CVE-2024-45733) by a user without the necessary permissions, as indicated in Splunk's internal Python logs (`splunk_python`).
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1210
    data_sources:
      - application
      - splunk
      - splunk_python
rules_count: 2
---

This threat concerns two critical vulnerabilities, CVE-2024-45731 and CVE-2024-45733, identified in Splunk Enterprise for Windows. Specifically, versions prior to 9.3.0, 9.2.3, and 9.1.6 are affected. These flaws enable a low-privileged user, even without 'admin' or 'power' Splunk roles, to write arbitrary files to the Windows system root directory, typically `C:\Windows\System32`, especially when Splunk is installed on a drive separate from the system root. This arbitrary file write, combined with an insecure session storage configuration, creates a path for remote code execution. Attackers can leverage this to upload and execute malicious code, leading to full system compromise. Detection engineers should prioritize identifying attempts to access vulnerable Splunk API endpoints and monitoring for unusual application creation events by unprivileged users.

## Attack Chain

1.  **Initial Access**: An attacker gains or already possesses a low-privileged user account on a Splunk Enterprise for Windows instance, lacking 'admin' or 'power' capabilities.
2.  **Exploit Initiation**: The attacker sends a specially crafted HTTP POST request to the vulnerable Splunk API endpoint, `/search/apps/local/_new`.
3.  **Arbitrary File Write (CVE-2024-45731)**: The successful request exploits CVE-2024-45731, allowing the attacker to write a malicious file (e.g., a DLL, executable, or script) to the Windows system root directory (`C:\Windows\System32`). This is particularly effective when Splunk is installed on a non-system drive.
4.  **Code Upload via Insecure Session Storage (CVE-2024-45733)**: The attacker leverages CVE-2024-45733's insecure session storage configuration to facilitate the upload and persistent storage of the malicious code.
5.  **Remote Code Execution**: The malicious file previously written to `C:\Windows\System32` is subsequently executed, leading to remote code execution on the underlying Splunk server.
6.  **System Compromise**: With RCE, the attacker gains elevated privileges and full control over the compromised Splunk server, enabling further actions.
7.  **Post-Exploitation Activities**: The attacker can now perform actions such as data exfiltration from Splunk's internal data, deploy additional malware for persistence, establish lateral movement, or disrupt Splunk operations.

## Impact

The successful exploitation of these vulnerabilities leads to remote code execution on the affected Splunk Enterprise for Windows server. This grants the attacker full control over the compromised system, potentially with SYSTEM-level privileges if the Splunk service runs as such. Consequences include unauthorized access to sensitive data processed and stored by Splunk, complete compromise of the Splunk environment, and the ability to pivot to other systems within the network. This can result in significant data breaches, operational disruption, and the establishment of persistent backdoors, impacting the integrity and availability of critical security and operational data.

## Recommendation

*   **Patch Immediately**: Apply patches for CVE-2024-45731 and CVE-2024-45733 by upgrading Splunk Enterprise for Windows to versions 9.3.0, 9.2.3, 9.1.6, or newer as per Splunk's advisories.
*   **Deploy Detection Rules**: Deploy the "Detect CVE-2024-45731/CVE-2024-45733 Exploitation Attempt - Splunk Vulnerable Endpoint Access" and "Detect CVE-2024-45731/CVE-2024-45733 Exploitation - Splunk Low-Privilege App Creation Error" Sigma rules to your SIEM.
*   **Monitor Splunk Internal Logs**: Ensure that `_internal` index logs, specifically `splunkd_access` and `splunk_python` sourcetypes, are being collected and monitored for suspicious activity.
*   **Investigate Detections**: Investigate any alerts generated by the provided Sigma rules for activities related to the `*/search/apps/local/_new` endpoint or privilege errors for low-privileged users.
