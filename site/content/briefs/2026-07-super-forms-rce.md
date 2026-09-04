---
title: WordPress Super Forms Plugin Arbitrary File Upload (CVE-2026-14894)
slug: 2026-07-super-forms-rce
description: An unauthenticated arbitrary file upload vulnerability (CVE-2026-14894) exists in the Super Forms - Drag & Drop Form Builder plugin for WordPress, affecting all versions up to and including 6.3.313, allowing unauthenticated attackers to upload executable files via the `submit_form` AJAX handler, leading to remote code execution after trivial nonce bypass.
date: "2026-07-10T04:19:23Z"
lastmod: "2026-09-04T09:42:10Z"
type: advisory
types:
  - advisory
severities:
  - critical
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=ED9BCDF7-AF28-577D-BF6D-43E2548BC780&utm_source=rss&utm_medium=rss
tags:
  - wordpress
  - plugin
  - arbitrary-file-upload
  - rce
  - web-exploit
vendors:
  - WordPress
  - Super Forms
products:
  - Super Forms – Drag & Drop Form Builder <= 6.3.313
  - Super Forms ≤ 6.3.313
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated arbitrary file upload vulnerability (CVE-2026-14894) exists in the Super Forms – Drag & Drop Form Builder plugin for WordPress... This makes it possible for unauthenticated attackers to upload files that may be executable.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This makes it possible for unauthenticated attackers to upload files that may be executable, which makes remote code execution possible.
    confidence_band: high
cves:
  - id: CVE-2026-14894
    cvss: 9.8
    epss: 0.03484
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14894
  - https://sploitus.com/exploit?id=ED9BCDF7-AF28-577D-BF6D-43E2548BC780&utm_source=rss&utm_medium=rss
  - https://thehackernews.com/2026/09/over-440000-exploit-attempts-target.html
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=ED9BCDF7-AF28-577D-BF6D-43E2548BC780
  - type: ip
    value: 103.168.147.235
  - type: ip
    value: 103.168.146.131
  - type: ip
    value: 103.154.152.178
  - type: ip
    value: 103.170.97.7
  - type: ip
    value: 182.10.130.51
  - type: ip
    value: 189.4.122.140
  - type: ip
    value: 129.227.46.143
  - type: ip
    value: 64.176.209.104
  - type: ip
    value: 103.164.182.122
  - type: ip
    value: 37.9.33.62
ioc_counts:
  ip: 10
  url: 1
rules:
  - title: Detects CVE-2026-14894 Exploitation - Web Shell Access via Super Forms Upload
    description: Detects CVE-2026-14894 exploitation attempts by monitoring web server logs for GET requests to common WordPress upload directories that include executable file extensions, indicative of a successfully uploaded web shell.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1059.006
      - T1505.003
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-07-11T14:01:30Z"
    level: L2
    summary: poc_available; OS linux
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=ED9BCDF7-AF28-577D-BF6D-43E2548BC780&utm_source=rss&utm_medium=rss
  - at: "2026-09-04T09:42:10Z"
    level: L1
    summary: new IOCs
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/09/over-440000-exploit-attempts-target.html
---

A critical arbitrary file upload vulnerability, identified as CVE-2026-14894, affects the Super Forms - Drag & Drop Form Builder plugin for WordPress, impacting all versions up to and including 6.3.313. This flaw stems from a critical absence of file type validation and capability checks within the `submit_form` nopriv AJAX handler. This means that unauthenticated attackers can upload executable files, paving the way for remote code execution (RCE) on the compromised WordPress instance. The primary hurdle for exploitation, a session nonce, is easily circumvented. Attackers can obtain a valid `sf_nonce` and session cookie through a separate, also unauthenticated, `super_create_nonce` AJAX action with a single prior request. This reduces the exploitation path to a simple two-step process, enabling an unauthenticated attacker to achieve full system compromise.

## Attack Chain

1. **Initial Access (Nonce Generation)**: An unauthenticated attacker sends an HTTP POST request to the WordPress `admin-ajax.php` endpoint with the `action=super_create_nonce` parameter to obtain a valid session nonce and corresponding session cookie.
2. **Preparation (Malicious File Crafting)**: The attacker crafts a malicious file, typically a web shell (e.g., `shell.php` or `cmd.php`), designed to execute arbitrary commands on the server.
3. **Initial Access (Arbitrary File Upload)**: The attacker sends a second unauthenticated HTTP POST request to `admin-ajax.php`, targeting the `action=submit_form` parameter, embedding the previously obtained nonce and the crafted malicious file.
4. **Persistence/Defense Evasion (File Placement)**: Due to the Super Forms plugin's missing file type validation and absence of capability checks, the server uploads and saves the malicious executable file to a publicly accessible directory (e.g., `/wp-content/uploads/superforms/`) on the WordPress instance.
5. **Execution (Web Shell Access)**: The attacker sends an HTTP GET request directly to the URL of the newly uploaded web shell (e.g., `/wp-content/uploads/superforms/shell.php`) to trigger its execution.
6. **Impact (Remote Code Execution)**: The web shell executes arbitrary commands supplied by the attacker, leading to remote code execution on the underlying server and full compromise of the WordPress environment.

## Impact

The successful exploitation of CVE-2026-14894 allows unauthenticated attackers to achieve remote code execution on affected WordPress websites. This can lead to complete server compromise, including data theft, website defacement, injection of malicious code into the website, or the use of the compromised server as a platform for further attacks. Given the plugin's popularity, a significant number of WordPress sites are potentially vulnerable, facing risks of complete loss of data integrity, confidentiality, and availability.

## Recommendation

* **Patch CVE-2026-14894 immediately**: Update the Super Forms - Drag & Drop Form Builder plugin to a version greater than 6.3.313 to remediate CVE-2026-14894.
* **Deploy the Sigma rule** in this brief to your SIEM to detect attempts to access uploaded web shells resulting from CVE-2026-14894 exploitation.
* **Monitor web server logs** for unusual GET requests to WordPress upload directories with executable file extensions as described in the detection rule.
* **Implement web application firewall (WAF) rules** to block requests to `/wp-admin/admin-ajax.php` that attempt to upload files with suspicious extensions or contain common web shell patterns.
