---
title: Critical Vulnerability in Podlove Podcast Publisher Plugin Allows Unauthenticated File Uploads Leading to RCE
slug: 2026-07-podlove-wordpress-rce
description: A critical vulnerability, CVE-2026-13001, in the Podlove Podcast Publisher plugin for WordPress, impacting versions up to and including 4.5.1, allows unauthenticated attackers to upload arbitrary files due to missing file type validation, potentially leading to remote code execution on the server.
date: "2026-07-14T20:40:50Z"
lastmod: "2026-07-15T20:04:27Z"
type: advisory
types:
  - advisory
severities:
  - critical
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=7EB20766-CE15-52F8-8606-681C9D45AAAF&utm_source=rss&utm_medium=rss
tags:
  - wordpress
  - plugin
  - vulnerability
  - file-upload
  - rce
vendors:
  - Podlove
products:
  - Podlove Podcast Publisher <= 4.5.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: ""
    evidence: upload arbitrary files on the affected site's server which may make remote code execution possible.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: remote code execution possible.
    confidence_band: high
cves:
  - id: CVE-2026-13001
    cvss: 9.8
    epss: 0.01079
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13001
  - https://github.com/podlove/podlove-publisher/commit/5b32468601e903bae2bcacfaf36ff583d2bc9387
  - https://plugins.trac.wordpress.org/browser/podlove-podcasting-plugin-for-wordpress/tags/4.4.2/lib/model/image.php#L439
  - https://plugins.trac.wordpress.org/changeset/3597461/podlove-podcasting-plugin-for-wordpress
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/f81a3429-f378-4295-adbe-ad6f1df59701?source=cve
  - https://sploitus.com/exploit?id=7EB20766-CE15-52F8-8606-681C9D45AAAF&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=7EB20766-CE15-52F8-8606-681C9D45AAAF
  - type: url
    value: https://github.com/shinthink/CVE-2026-13001.git
  - type: url
    value: https://raw.githubusercontent.com/shinthink/payloads/main/shell.gif
  - type: url
    value: https://github.com/Raimu0x19/CVE-2026-13001
ioc_counts:
  url: 4
rules:
  - title: Detects CVE-2026-13001 Exploitation - Malicious File Upload via Podlove Podcast Publisher
    description: Detects exploitation of CVE-2026-13001 by monitoring HTTP POST requests to the Podlove Podcast Publisher plugin's cache file handler with suspicious file extensions, indicative of arbitrary file upload attempts.
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
updates:
  - at: "2026-07-15T20:04:27Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=7EB20766-CE15-52F8-8606-681C9D45AAAF&utm_source=rss&utm_medium=rss
---

A severe vulnerability, identified as CVE-2026-13001, affects the Podlove Podcast Publisher plugin for WordPress, specifically in all versions up to and including 4.5.1. This flaw stems from inadequate file type validation within the `podlove_handle_cache_files` function, which attackers can exploit. This allows unauthenticated adversaries to upload arbitrary files, including malicious scripts such as web shells, directly to the vulnerable WordPress site's server. The absence of proper validation grants threat actors a direct path to establish persistence, execute arbitrary code, and potentially gain full control over the compromised web server. Such an attack could lead to data exfiltration, website defacement, or further compromise of the hosting environment.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress instance running the vulnerable Podlove Podcast Publisher plugin.
2. The attacker crafts an HTTP POST request targeting the `podlove_handle_cache_files` function endpoint on the vulnerable server.
3. Within this POST request, the attacker includes a malicious file, such as a PHP web shell (e.g., `shell.php`), bypassing typical file type checks.
4. Due to the missing file type validation in the plugin's `podlove_handle_cache_files` function, the server accepts and processes the malicious file upload.
5. The plugin saves the uploaded malicious file to a publicly accessible directory on the web server.
6. The attacker then navigates to the URL of the uploaded web shell (e.g., `https://example.com/wp-content/uploads/cache/shell.php`) via a web browser.
7. Upon accessing the web shell, the attacker can execute arbitrary commands on the underlying server, leveraging the web server's privileges.
8. Successful command execution grants the attacker remote code execution capabilities, enabling further compromise of the system or network.

## Impact

Successful exploitation of CVE-2026-13001 results in unauthenticated remote code execution on the affected WordPress server. This critical access allows attackers to completely compromise the web server, leading to potential data breaches, website defacement, denial-of-service attacks, or using the compromised server as a launching pad for further attacks within the network. Organizations running the vulnerable plugin face significant risks of operational disruption, reputational damage, and severe financial and legal repercussions due to data loss or exposure.

## Recommendation

* Patch CVE-2026-13001 immediately by updating the Podlove Podcast Publisher plugin to a version greater than 4.5.1.
* Deploy the provided Sigma rule to your SIEM system to detect suspicious file uploads targeting WordPress.
* Enable comprehensive web server access logging, particularly for HTTP POST requests and unusual file extensions (e.g., `.php`, `.phar`, `.jsp`) in upload directories.
