---
title: Critical RCE Vulnerability in Blocksy Companion Pro WordPress Plugin (CVE-2026-58480)
slug: 2026-07-wordpress-blocksy-file-upload-rce
description: An unauthenticated arbitrary file upload vulnerability (CVE-2026-58480) in Blocksy Companion Pro plugin for WordPress versions prior to 2.1.47 allows attackers to bypass extension validation via double-extension files, leading to remote code execution by forcing the web server to execute uploaded PHP files.
date: "2026-07-08T14:19:33Z"
lastmod: "2026-07-26T10:00:37Z"
type: advisory
types:
  - advisory
severities:
  - critical
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=EDE1A579-A410-5EA8-ACAE-60A03E18B511&utm_source=rss&utm_medium=rss
tags:
  - wordpress
  - plugin
  - rce
  - file-upload
  - web
vendors:
  - Blocksy
  - WordPress
  - WordPress Foundation
products:
  - Blocksy Companion Pro plugin < 2.1.47
  - WordPress
  - Blocksy Companion Pro (< 2.1.47)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1609
    technique_name: Drive-by Compromise
    evidence: unauthenticated arbitrary file upload vulnerability that allows attackers to upload executable files
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: the web server executes the file as PHP, achieving remote code execution
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    evidence: upload executable files by bypassing extension validation... leading the web server to execute the file as PHP, achieving remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-58480
    cvss: 9.8
    epss: 0.00605
  - id: CVE-2026-15158
    cvss: 9.8
    epss: 0.00611
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58480
  - https://sploitus.com/exploit?id=EDE1A579-A410-5EA8-ACAE-60A03E18B511&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=EDE1A579-A410-5EA8-ACAE-60A03E18B511
ioc_counts:
  url: 1
rules:
  - title: Detects CVE-2026-58480 Exploitation - Blocksy Companion Pro File Upload Bypass
    description: Detects CVE-2026-58480 exploitation attempts by monitoring suspicious file upload requests to WordPress admin-ajax.php with double extensions that bypass validation, indicative of arbitrary file upload leading to RCE in Blocksy Companion Pro plugin.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
      - persistence
    techniques:
      - T1059.006
      - T1190
      - T1505.004
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-07-26T10:00:37Z"
    level: L2
    summary: poc_available; added CVE-2026-15158
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=EDE1A579-A410-5EA8-ACAE-60A03E18B511&utm_source=rss&utm_medium=rss
---

A critical unauthenticated arbitrary file upload vulnerability, tracked as CVE-2026-58480, has been identified in the Blocksy Companion Pro plugin for WordPress, affecting all versions prior to 2.1.47. This flaw enables remote attackers to achieve arbitrary code execution on vulnerable WordPress installations. The vulnerability resides within the `save_attachments` function, exposed through the Advanced Reviews feature, where inadequate extension validation allows attackers to upload executable files. Specifically, a flawed `strpos()` substring check in the Custom Fonts extension's validation mechanism can be bypassed by using double-extension filenames (e.g., `shell.woff2.php`). This bypass tricks the web server into executing the uploaded file as PHP, giving attackers full control over the compromised website. This vulnerability presents a significant risk to affected organizations, allowing for website defacement, data theft, or further network compromise.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site running the Blocksy Companion Pro plugin version prior to 2.1.47.
2. The attacker crafts a malicious file, such as `shell.woff2.php`, containing PHP code.
3. The attacker sends an HTTP POST request to the `save_attachments` function, which is exposed via the Advanced Reviews feature, attempting to upload the malicious file. This likely targets the `admin-ajax.php` endpoint.
4. The plugin's validation process, specifically the `strpos()` check in the Custom Fonts extension, mistakenly passes the filename `shell.woff2.php` because it contains the `.woff2` substring.
5. The `save_attachments` function proceeds with the upload, placing the file on the web server.
6. The web server, recognizing the `.php` extension, attempts to execute the uploaded file as a PHP script when accessed, leading to remote code execution.
7. The attacker gains arbitrary code execution, typically establishing a web shell for persistent access and further compromise.

## Impact

The successful exploitation of CVE-2026-58480 leads to full remote code execution on the compromised WordPress server. This allows attackers to deface websites, inject malicious content, exfiltrate sensitive data (e.g., customer information, intellectual property), establish persistent access via web shells, and potentially pivot to other systems within the network. For businesses relying on WordPress for e-commerce, content delivery, or lead generation, this can result in significant financial losses, reputational damage, and regulatory penalties. The high CVSS score of 9.8 reflects the critical nature of this unauthenticated RCE.

## Recommendation

* Immediately update the Blocksy Companion Pro plugin to version 2.1.47 or later to patch CVE-2026-58480.
* Deploy the Sigma rule "Detects CVE-2026-58480 Exploitation - Blocksy Companion Pro File Upload Bypass" to your SIEM to detect attempts to exploit this vulnerability.
* Enable detailed webserver logging (e.g., Apache access logs, Nginx access logs) to capture full HTTP request details, including URI stems, query strings, and request methods, which are crucial for the detection rule.
* Regularly review web server access logs for suspicious file uploads to `/wp-content/uploads/` or other writable directories, especially for files with double extensions.
