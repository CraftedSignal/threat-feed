---
title: Arbitrary File Upload Vulnerability in Snazzy Social Media Feed Plugin
slug: 2026-10-snazzy-social-media-feed-rce
description: The Snazzy Social Media Feed WordPress plugin (up to version 2.5) is susceptible to arbitrary file upload and remote code execution via insufficient sanitization in the standalone save-to-cache.php script.
date: "2026-10-14T04:35:28Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:snazzy_social_media_feed_project:snazzy_social_media_feed:*:*:*:*:*:wordpress:*:*
tags:
  - web-vulnerability
  - wordpress
  - cve-2026-110002
  - rce
products:
  - Snazzy Social Media Feed (<= 2.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The standalone save-to-cache.php script is directly reachable without loading WordPress; combined with insufficient sanitization... makes remote code execution possible.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This allows an attacker to inject arbitrary PHP code, which is then immediately executable.
    confidence_band: high
cves:
  - id: CVE-2026-110002
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110002
rules:
  - title: Detect CVE-2026-110002 Exploitation - Arbitrary File Upload via save-to-cache.php
    description: Detects attempts to exploit CVE-2026-110002 by sending suspicious requests to the vulnerable save-to-cache.php script.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block access to /wp-content/plugins/snazzy-social-media-feed/save-to-cache.php at the WAF or web server level
      owner: SOC
      due: 24h
      evidence: CVE-2026-110002 indicates the script is the primary vector for RCE
  mitigation_plan:
    - priority: immediate
      action: Upgrade or disable the Snazzy Social Media Feed plugin
      owner: IT Operations
      addresses: CVE-2026-110002
      evidence: Source states versions up to 2.5 are vulnerable
---

The Snazzy Social Media Feed plugin for WordPress contains a critical vulnerability (CVE-2026-110002) affecting all versions up to and including 2.5. The flaw resides in the 'save-to-cache.php' file, which operates as a standalone script without the standard WordPress environment, authentication, capability checks, or nonce validation. An attacker with subscriber-level access or higher can exploit this by manipulating the 'pluginURL' parameter. Due to the use of 'FILTER_SANITIZE_URL', which fails to remove critical PHP syntax characters, the input is written directly into 'cached-content/cached-feed.php'. This allows an attacker to inject arbitrary PHP code, which is then immediately executable by requesting the file directly. This vulnerability provides a direct vector for remote code execution on the underlying web server.

## Attack Chain

1. Attacker authenticates as a user with subscriber-level privileges or higher on the target WordPress site.
2. Attacker crafts a malicious request containing a PHP payload designed to execute system commands.
3. Attacker sends an HTTP POST or GET request to the vulnerable endpoint: /wp-content/plugins/snazzy-social-media-feed/save-to-cache.php.
4. The request includes the 'pluginURL' parameter containing the malicious PHP code disguised as a URL.
5. The 'save-to-cache.php' script fails to validate the request or sanitize the input beyond 'FILTER_SANITIZE_URL', allowing the payload to pass.
6. The script writes the malicious payload verbatim into the file 'cached-content/cached-feed.php'.
7. Attacker triggers the malicious code by sending a GET request to the newly created 'cached-content/cached-feed.php' file.
8. The web server executes the payload, granting the attacker arbitrary code execution privileges.

## Impact

Successful exploitation of this vulnerability allows an authenticated attacker to achieve full remote code execution on the web server. This could lead to a complete site compromise, data exfiltration, lateral movement within the hosting environment, and the installation of persistent backdoors. Given the ubiquity of WordPress installations, this vulnerability poses a significant risk to any organization running the affected plugin versions.

## Recommendation

* Immediately update the Snazzy Social Media Feed plugin to a version released after 2.5, if available.
* If no patch is available, deactivate and remove the Snazzy Social Media Feed plugin until a secure version is confirmed by the vendor.
* Monitor web server access logs for anomalous requests to 'save-to-cache.php' containing unusual 'pluginURL' parameters.
* Implement strict file permissions on the WordPress 'plugins' and 'uploads' directories to prevent web-executable files from being created or executed.
* Use WAF rules to block requests to '/wp-content/plugins/snazzy-social-media-feed/save-to-cache.php' unless explicitly required.
