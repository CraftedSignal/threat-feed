---
title: EGroupware Critical RCE Vulnerability (CVE-2026-27823)
slug: 2026-07-egroupware-rce
description: A critical remote code execution vulnerability (CVE-2026-27823) in EGroupware allows an authenticated attacker, or an unauthenticated attacker if self-registration is enabled, to execute arbitrary commands on the server by combining an authorization bypass, arbitrary file write via path traversal, and arbitrary file read, leading to full system compromise.
date: "2026-07-07T13:12:53Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - RCE
  - web-vulnerability
  - egroupware
  - php
  - critical
  - exploit
vendors:
  - EGroupware
products:
  - composer/egroupware/egroupware (>= 26.0.20251208, < 26.2.20260224)
  - composer/egroupware/egroupware (< 23.1.20260224)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The issue allows an authenticated attacker to execute arbitrary commands on the server. If user self-registration is enabled, the vulnerability may be exploitable without prior authentication.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server Software Component
    evidence: 'By combining: Arbitrary file read... Arbitrary file write (to overwrite it with modified content), an attacker can inject controlled PHP code while preserving file validity. This results in Remote Code Execution...'
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: An alternative impact includes modifying the admin setup password to gain full system control.
    confidence_band: med
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: 'A second vulnerability allows arbitrary file read via: /egroupware/index.php?menuaction=importexport.importexport_export_ui.download&_filename=../../../usr/share/egroupware/header.inc.php... This allows retrieving the original header.inc.php content.'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-h9qx-v5xp-ph8p
rules:
  - title: Detects CVE-2026-27823 Exploitation - EGroupware Auth Bypass & File Write Attempt
    description: Detects attempts to exploit CVE-2026-27823 by identifying POST requests to EGroupware's ajax_upload function with a crafted 'participant_role' to bypass authorization and potential path traversal in 'video_type' for arbitrary file write.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
      - T1505.003
    data_sources:
      - webserver
  - title: Detects CVE-2026-27823 Exploitation - EGroupware Arbitrary File Read Attempt
    description: Detects attempts to exploit CVE-2026-27823 by identifying GET requests to EGroupware's importexport_export_ui::download function with path traversal in the '_filename' parameter for arbitrary file read.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - discovery
    techniques:
      - T1560
      - T1592
    data_sources:
      - webserver
rules_count: 2
---

A critical remote code execution (RCE) vulnerability, tracked as CVE-2026-27823, has been discovered in EGroupware, an open-source collaboration suite. This flaw allows an authenticated attacker to execute arbitrary code on the underlying server. In environments where user self-registration is enabled, the vulnerability can be exploited by an unauthenticated attacker, significantly broadening its impact. Discovered by Huong Kieu of Cenobe Security, the vulnerability stems from a chain of weaknesses: an improper authorization check in the `SmallPartMediaRecorder::ajax_upload()` function, which can be bypassed via crafted request data, an arbitrary file write due to path traversal, and a separate arbitrary file read vulnerability in `importexport_export_ui::download`. By combining these, attackers can overwrite critical PHP files, inject malicious code, and achieve full system compromise. The vulnerability affects `composer/egroupware/egroupware` versions prior to `23.1.20260224` and versions `26.0.20251208` through `26.1.20260223`.

## Attack Chain

1.  **Initial Access / Authentication Bypass**: An attacker, potentially unauthenticated if self-registration is enabled, crafts a POST request to `/egroupware/json.php` targeting the `SmallPartMediaRecorder::ajax_upload()` function.
2.  **Authorization Bypass**: The crafted request includes a manipulated JSON body with `participant_role` set to `3` (ROLE_TEACHER), bypassing the `isTeacher` check intended to restrict file uploads.
3.  **Arbitrary File Write**: Following the authorization bypass, the attacker exploits a path traversal vulnerability via the `video_type` parameter to write an arbitrary file to a controlled path, such as `./header.inc.php`.
4.  **Arbitrary File Read**: A separate vulnerability is exploited by making a GET request to `/egroupware/index.php?menuaction=importexport.importexport_export_ui.download` with a malicious `_filename` parameter (e.g., `../../../usr/share/egroupware/header.inc.php`) to read the original content of the target file.
5.  **Code Injection Preparation**: The attacker combines the original `header.inc.php` content with injected PHP code (e.g., a webshell or administrative credential modification logic) to preserve file validity and ensure continued server operation.
6.  **Remote Code Execution**: The attacker overwrites `header.inc.php` using the arbitrary file write vulnerability with the crafted content, leading to Remote Code Execution when the file is subsequently loaded by the web server.

## Impact

Successful exploitation of CVE-2026-27823 leads to critical consequences, including full system compromise and complete takeover of the EGroupware instance. Attackers can gain arbitrary remote code execution on the server, allowing them to install backdoors, exfiltrate sensitive data, manipulate or destroy data, or pivot to other systems within the network. This could result in significant data breaches, operational disruption, and reputational damage for affected organizations. The ability to modify administrative setup passwords further enables persistent control over the EGroupware application.

## Recommendation

*   **Patch CVE-2026-27823 immediately**: Upgrade EGroupware `composer/egroupware/egroupware` to version `23.1.20260224` or `26.2.20260224` to mitigate CVE-2026-27823.
*   **Disable user self-registration**: If not strictly necessary, disable user self-registration in EGroupware to reduce the attack surface for unauthenticated exploitation of CVE-2026-27823.
*   **Deploy the Sigma rules in this brief**: Integrate the provided Sigma rules into your SIEM to detect attempts at exploiting the authorization bypass, arbitrary file write, and arbitrary file read components of CVE-2026-27823.
*   **Enable webserver logging**: Ensure comprehensive logging for your EGroupware web server (access logs, error logs) to capture HTTP requests including method, URI, query parameters, and POST body details, which are critical for activating the detection rules.
