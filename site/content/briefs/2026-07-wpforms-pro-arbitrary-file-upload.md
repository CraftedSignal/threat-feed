---
title: WPForms Pro Plugin Arbitrary File Upload Vulnerability Leading to RCE
slug: 2026-07-wpforms-pro-arbitrary-file-upload
description: The WPForms Pro plugin for WordPress, in versions up to and including 1.10.1.1, is vulnerable to arbitrary file upload via the ajax_chunk_upload_finalize function, allowing unauthenticated attackers to upload executable files due to improper file type validation occurring after file contents are written to disk, which can lead to remote code execution on the affected server.
date: "2026-07-25T07:18:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - rce
  - arbitrary-file-upload
  - web-vulnerability
vendors:
  - WPForms
products:
  - WPForms Pro plugin for WordPress <= 1.10.1.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to upload files that may be executable, which makes remote code execution possible.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server Software Component
    evidence: This makes it possible for unauthenticated attackers to upload files that may be executable, which makes remote code execution possible.
    confidence_band: high
cves:
  - id: CVE-2026-10818
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10818
rules:
  - title: Detects CVE-2026-10818 Exploitation - WPForms Pro Arbitrary File Upload Attempt
    description: Detects exploitation attempts against CVE-2026-10818, an arbitrary file upload vulnerability in WPForms Pro plugin, by looking for POST requests to the ajax_chunk_upload_finalize function with suspicious executable file extensions.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
      - T1505.003
    data_sources:
      - webserver
rules_count: 1
---

The WPForms Pro plugin for WordPress, specifically all versions up to and including 1.10.1.1, contains a critical arbitrary file upload vulnerability tracked as CVE-2026-10818. This flaw resides within the `ajax_chunk_upload_finalize` function, where file type validation occurs *after* chunk metadata and file contents have already been written to the server's disk. Compounding the issue, the plugin fails to delete these assembled files even when validation ultimately fails. This design defect permits unauthenticated attackers to upload potentially executable files, such as PHP web shells, to the WordPress installation. Successful exploitation can lead to full remote code execution on the underlying web server, allowing threat actors to gain control of the compromised system, exfiltrate sensitive data, or further compromise the network.

## Attack Chain

1. An unauthenticated attacker sends a crafted HTTP POST request to the WordPress site.
2. The request targets the `admin-ajax.php` endpoint, specifically invoking the `ajax_chunk_upload_finalize` function of the WPForms Pro plugin, including a malicious file payload (e.g., a PHP web shell) and chunk metadata.
3. Due to the vulnerability (CVE-2026-10818), the plugin processes and writes the malicious file content to a temporary location on disk *before* performing any file type validation.
4. The plugin then attempts file type validation against the uploaded content.
5. This validation subsequently fails because the uploaded file is an executable script (e.g., `.php`), not an allowed file type.
6. Critically, despite the validation failure, the plugin does not delete the temporarily assembled malicious file from the web server's disk, leaving it accessible.
7. The attacker identifies the storage location of the uploaded malicious file (e.g., `shell.php`) and accesses it directly via a subsequent HTTP GET request.
8. Executing the uploaded web shell achieves Remote Code Execution (RCE) on the compromised web server, allowing the attacker to run arbitrary commands.

## Impact

Successful exploitation of CVE-2026-10818 grants unauthenticated attackers remote code execution capabilities on the affected WordPress server. This means an attacker can completely compromise the web server, leading to data breaches, website defacement, arbitrary data modification or deletion, and potentially using the compromised server as a pivot point for further attacks into the internal network. The total number of affected WordPress sites running WPForms Pro is currently unknown, but given the plugin's popularity, a significant number of installations could be at risk if not patched promptly.

## Recommendation

* Patch CVE-2026-10818 immediately by updating the WPForms Pro plugin to version 1.10.1.2 or higher on all WordPress installations.
* Deploy the Sigma rule "Detects CVE-2026-10818 Exploitation - WPForms Pro Arbitrary File Upload Attempt" to your SIEM to identify attempts to exploit this vulnerability against the `ajax_chunk_upload_finalize` function.
* Review web server access logs for requests to `admin-ajax.php` with `action=wpforms_pro_ajax_chunk_upload_finalize` followed by subsequent GET requests to newly created PHP, JSP, ASPX, or other executable files.
