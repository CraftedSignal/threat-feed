---
title: Chamilo LMS Unrestricted File Upload Leads to Remote Code Execution
slug: 2024-01-29-chamilo-rce
description: An unrestricted file upload vulnerability in Chamilo LMS (CVE-2026-32931) allows an authenticated teacher to upload a PHP webshell, leading to remote code execution.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - chamilo
  - rce
  - file-upload
vendors:
  - Chamilo
products:
  - Chamilo LMS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server Software Component
cves:
  - id: CVE-2026-32931
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32931
rules:
  - title: Chamilo LMS Webshell Upload via Content-Type Spoofing
    description: Detects attempts to upload PHP webshells to Chamilo LMS by spoofing the Content-Type header.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1505.001
    data_sources:
      - webserver
      - linux
  - title: Chamilo LMS Suspicious PHP File Access in Upload Directory
    description: Detects access to PHP files within the Chamilo LMS upload directory, which could indicate webshell activity.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Chamilo LMS, a learning management system, is vulnerable to an unrestricted file upload (CVE-2026-32931). This flaw affects versions prior to 1.11.38 and 2.0.0-RC.3. A teacher, after successful authentication, can exploit the exercise sound upload function to inject a PHP webshell. By manipulating the Content-Type header to appear as "audio/mpeg", the attacker bypasses file type restrictions. The malicious PHP file is then stored in a publicly accessible web directory. This leads to remote code execution, granting the attacker control with the privileges of the web server user (www-data). Successful exploitation allows attackers to compromise the Chamilo LMS server, potentially leading to data theft, defacement, or further lateral movement within the network.

## Attack Chain

1.  The attacker authenticates to the Chamilo LMS as a teacher.
2.  The attacker navigates to the exercise sound upload function within the Chamilo LMS interface.
3.  The attacker crafts a malicious PHP webshell (e.g., `evil.php`).
4.  The attacker intercepts the file upload request and modifies the `Content-Type` header to `audio/mpeg`.
5.  The attacker uploads the PHP webshell, which is then saved with its original `.php` extension to a web-accessible directory on the server.
6.  The attacker accesses the uploaded PHP webshell (e.g., `/upload/evil.php`) via a web browser.
7.  The PHP webshell executes arbitrary commands on the server with the privileges of the web server user (www-data).
8.  The attacker can then use the webshell for further malicious activities such as reconnaissance, lateral movement, or data exfiltration.

## Impact

Successful exploitation of CVE-2026-32931 allows an attacker to execute arbitrary code on the Chamilo LMS server. The attacker gains control with the privileges of the web server user, potentially leading to sensitive data theft, complete system compromise, or further attacks on internal infrastructure. Given the nature of LMS systems, this could expose student records, course materials, and other confidential information, leading to a significant breach of privacy and security.

## Recommendation

*   Upgrade Chamilo LMS to version 1.11.38 or 2.0.0-RC.3 to patch CVE-2026-32931.
*   Implement web application firewall (WAF) rules to inspect and block file uploads with suspicious Content-Type headers that do not match the file extension.
*   Monitor web server logs for access to unusual PHP files in upload directories, which may indicate successful exploitation. Deploy the provided Sigma rule to assist in this monitoring.
*   Implement strict file upload policies and validate file types on the server side, regardless of the Content-Type header provided by the client.
