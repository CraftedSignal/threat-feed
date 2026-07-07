---
title: Paymenter vulnerable to Remote Code Execution via public file uploads
slug: 2026-07-paymenter-rce-file-upload
description: A critical remote code execution (RCE) vulnerability, CVE-2025-58048, in Paymenter's ticket attachments functionality allows an authenticated, low-privileged user to upload arbitrary files, leading to full compromise of the application and underlying server, enabling attackers to extract sensitive data, read credentials, and execute arbitrary system commands.
date: "2026-07-03T11:08:47Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - remote-code-execution
  - web-application
  - php
  - critical-vulnerability
  - file-upload
  - webshell
vendors:
  - Paymenter
products:
  - Paymenter (< 1.2.11)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Running arbitrary system commands under the web server user context.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Local System
    evidence: Extracting sensitive data from the database (e.g. customer information).
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: Reading credentials from .env or other configuration files.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Reading credentials from .env or other configuration files.
    confidence_band: high
cves:
  - id: CVE-2025-58048
    cvss: 9.9
    epss: 0.00374
references:
  - https://github.com/advisories/GHSA-5pm9-r2m8-rcmj
  - https://github.com/Paymenter/Paymenter/commit/87c3db42282ada1e3cda54b9a01f846926c0669b
  - https://github.com/Paymenter/Paymenter/releases/tag/v1.2.11
iocs:
  - type: url
    value: https://github.com/Paymenter/Paymenter/commit/87c3db42282ada1e3cda54b9a01f846926c0669b
  - type: url
    value: https://github.com/Paymenter/Paymenter/releases/tag/v1.2.11
ioc_counts:
  url: 2
---

A critical remote code execution (RCE) vulnerability, tracked as CVE-2025-58048, has been identified in Paymenter, a billing and client management software. This flaw specifically impacts the ticket attachments functionality, allowing a malicious authenticated user with low privileges to upload arbitrary files to the server. These files, when placed in a publicly accessible directory and subsequently executed due to improper web server configuration, grant attackers full control over the application and the underlying server. Exploitation enables malicious actors to extract sensitive data, including customer information from the database, read credentials from configuration files such as `.env`, and execute arbitrary system commands under the context of the web server user. The vulnerability is present in versions prior to v1.2.11 and was patched in commit `87c3db42282ada1e3cda54b9a01f846926c0669b`, released as v1.2.11.

## Attack Chain

1.  An authenticated, low-privileged user logs into the Paymenter application and accesses the ticket attachments functionality.
2.  The attacker crafts and uploads a malicious file, such as a webshell (e.g., `shell.php`), masquerading it as a legitimate attachment.
3.  The Paymenter application processes the upload and stores the malicious file in a publicly accessible directory, typically `/storage/`.
4.  The attacker then directly accesses the uploaded malicious file (e.g., `https://[paymenter_domain]/storage/shell.php`) via a web browser or automated tool.
5.  Due to an insecure web server configuration (e.g., Nginx serving `/storage/` files without forcing a download), the server executes the malicious file instead of serving it as static content.
6.  The executed webshell grants the attacker Remote Code Execution (RCE) capabilities under the web server's user context.
7.  Leveraging RCE, the attacker extracts sensitive data from the database, reads credentials from configuration files (e.g., `.env`), or executes arbitrary system commands to further compromise the server.

## Impact

This vulnerability is deemed Critical as it allows a low-privilege authenticated user to fully compromise the Paymenter application and its underlying server. If exploited, attackers can gain unauthorized access to sensitive customer information stored in the database, pilfer critical credentials from `.env` or other configuration files, and execute arbitrary system commands. This level of access permits complete control over the affected system, enabling data exfiltration, further lateral movement, and potential disruption of services. While specific victim counts are not available, any Paymenter installation running a vulnerable version is at risk, particularly those that handle customer data and payments.

## Recommendation

*   **Patch CVE-2025-58048 immediately:** Upgrade Paymenter to version v1.2.11 or later as described in the patches section of this brief.
*   **Apply Nginx mitigation:** If immediate upgrade is not possible, implement the provided Nginx configuration to force downloads for files in the `/storage/` directory, preventing their execution as described in the content section.
*   **Deploy WAF controls:** Utilize a Web Application Firewall (WAF) to disallow direct access to the `/storage/` directory, as mentioned in the workaround section, until the patch can be applied.
