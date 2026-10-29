---
brief_id: brief-2026-06-mdjm-wordpress-rce
event_id: brief-2026-06-mdjm-wordpress-rce
revision: 1
activity_at: "2026-06-14T23:21:54Z"
title: Arbitrary File Upload in MDJM Event Management Plugin for WordPress (CVE-2026-7537)
slug: 2026-06-mdjm-wordpress-rce
description: Authenticated attackers with administrator-level privileges can exploit an arbitrary file upload vulnerability (CVE-2026-7537) in the MDJM Event Management plugin for WordPress (versions <= 1.7.8.3) via the `mdjm_send_comm_email` function due to lack of file validation, enabling remote code execution.
date: "2026-06-14T23:21:54Z"
lastmod: "2026-10-29T02:48:59Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-D0N601-CVE-2026-7537&utm_source=rss&utm_medium=rss
tags:
  - wordpress
  - plugin
  - rce
  - file-upload
  - cve
  - webserver
vendors:
  - MDJM
  - WordPress
products:
  - MDJM Event Management plugin (<= 1.7.8.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-7537
    cvss: 7.2
    epss: 0.00659
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7537
  - https://github.com/d0n601/CVE-2026-7537
  - https://plugins.trac.wordpress.org/browser/mobile-dj-manager/tags/1.7.8.2/includes/admin/communications/comms-functions.php#L241
  - https://plugins.trac.wordpress.org/browser/mobile-dj-manager/tags/1.7.8.2/includes/admin/communications/comms-functions.php#L248
  - https://plugins.trac.wordpress.org/browser/mobile-dj-manager/tags/1.7.8.3/includes/admin/communications/comms-functions.php#L241
  - https://plugins.trac.wordpress.org/browser/mobile-dj-manager/tags/1.7.8.3/includes/admin/communications/comms-functions.php#L248
  - https://plugins.trac.wordpress.org/browser/mobile-dj-manager/trunk/includes/admin/communications/comms-functions.php#L241
  - https://plugins.trac.wordpress.org/browser/mobile-dj-manager/trunk/includes/admin/communications/comms-functions.php#L248
  - https://plugins.trac.wordpress.org/changeset?sfp_email=&sfph_mail=&reponame=&old=3528037%40mobile-dj-manager&new=3528037%40mobile-dj-manager&sfp_email=&sfph_mail=
  - https://ryankozak.com/posts/cve-2026-7537/
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/42f37a41-deff-4b17-94d8-4e0fd1ce22c2?source=cve
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-D0N601-CVE-2026-7537&utm_source=rss&utm_medium=rss
rules:
  - title: Detects CVE-2026-7537 Exploitation - Malicious Script Upload Attempt
    description: Detects CVE-2026-7537 exploitation — HTTP POST requests to WordPress AJAX handler with known executable file extensions in the URI query or request body, indicative of an arbitrary file upload attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-7537 Exploitation - Web Shell Access in Uploads Directory
    description: Detects CVE-2026-7537 exploitation — HTTP requests attempting to access executable files (potential web shells) within the WordPress wp-content/uploads directory, indicating post-exploitation activity.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059
      - T1071.001
    data_sources:
      - webserver
rules_count: 2
updates:
  - at: "2026-10-29T02:48:59Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-D0N601-CVE-2026-7537&utm_source=rss&utm_medium=rss
---

A critical vulnerability, CVE-2026-7537, has been identified in the MDJM Event Management plugin for WordPress, affecting all versions up to and including 1.7.8.3. This flaw, classified as an Arbitrary File Upload (CWE-434), resides within the `mdjm_send_comm_email` function. The vulnerability stems from an absence of proper file type, extension, or MIME type validation on uploaded files, allowing authenticated attackers with administrator-level access or higher to upload executable content. Successful exploitation leads directly to remote code execution on the underlying server hosting the WordPress instance. This vulnerability poses a significant risk to organizations using the affected plugin, as it can result in full server compromise, data exfiltration, or further network penetration.

## Attack Chain

1. An attacker obtains administrator-level credentials for a WordPress instance running the vulnerable MDJM Event Management plugin.
2. The attacker logs into the WordPress administrative dashboard with the compromised credentials.
3. The attacker prepares a malicious file, such as a PHP web shell, designed to execute arbitrary commands.
4. The attacker navigates to the plugin's interface where the `mdjm_send_comm_email` function is triggered, likely via an AJAX call to `wp-admin/admin-ajax.php`.
5. The malicious file is uploaded through the vulnerable function, bypassing all file type and MIME validation checks due to the flaw.
6. The web server processes and stores the executable malicious file in a publicly accessible directory, typically within `wp-content/uploads/` or a plugin-specific folder.
7. The attacker accesses the newly uploaded web shell via a direct HTTP request (e.g., GET request), executing arbitrary commands on the server.
8. Remote Code Execution is achieved, providing the attacker with control over the WordPress instance and the underlying server.

## Impact

Successful exploitation of CVE-2026-7537 can lead to severe consequences for affected organizations. The primary impact is remote code execution, granting attackers full control over the compromised WordPress server. This allows for data exfiltration from the web server and database, defacement of the website, injection of malicious content, and establishment of persistent access. Attackers can also use the compromised server as a staging ground for further attacks against internal networks. The administrative access requirement limits the immediate scope but increases the severity for organizations whose admin credentials are stolen or weak.

## Recommendation

* Immediately update the MDJM Event Management plugin to a patched version beyond 1.7.8.3.
* Deploy the Sigma rules provided in this brief to your SIEM to detect exploitation attempts.
* Implement web application firewall (WAF) rules to block suspicious file uploads, specifically requests to `wp-admin/admin-ajax.php` containing known executable file extensions, as described in the `Detects CVE-2026-7537 Exploitation - Malicious Script Upload Attempt` rule.
* Enable comprehensive web server logging for HTTP requests, including full URI, method, and response codes, to activate the rules and monitor for abnormal activity.
* Monitor for unexpected file creations in WordPress upload directories, especially files with executable extensions like `.php`, as highlighted by the `Detects CVE-2026-7537 Exploitation - Web Shell Access in Uploads Directory` rule.
