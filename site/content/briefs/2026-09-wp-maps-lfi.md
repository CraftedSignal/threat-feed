---
title: Local File Inclusion Vulnerability in WP Maps Plugin
slug: 2026-09-wp-maps-lfi
description: An authenticated local file inclusion vulnerability in the WP Maps plugin allows subscribers to execute arbitrary PHP files on WordPress servers via the page parameter.
date: "2026-09-25T08:55:57Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wp_maps:wp_maps:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - vulnerability
  - lfi
vendors:
  - WordPress
products:
  - WP Maps – Google Maps,OpenStreetMap,Mapbox,Store Locator,Listing,Directory & Filters (<= 4.9.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: This makes it possible for authenticated attackers to include and execute arbitrary .php files on the server.
    confidence_band: high
cves:
  - id: CVE-2026-13456
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13456
rules:
  - title: Detects CVE-2026-13456 Exploitation - LFI via WP Maps Plugin
    description: Detects attempts to exploit CVE-2026-13456 by looking for path traversal sequences in the page parameter targeting the WP Maps plugin.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1202
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Update WP Maps plugin to the latest version.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-13456 necessitates patching.
  enrichment_needed:
    - item: Exploit availability
      owner: CTI
      reason: Assess if public exploit code increases immediate risk.
      evidence: CVE-2026-13456
  hunt_leads:
    - lead: Search web logs for 'page=' followed by directory traversal patterns.
      technique_id: T1202
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source description of LFI vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Upgrade plugin.
      owner: IT Operations
      addresses: CVE-2026-13456
      evidence: NVD vulnerability details.
---

The WP Maps WordPress plugin, specifically versions 4.9.8 and earlier, contains a critical security flaw categorized as Local File Inclusion (LFI). This vulnerability resides in the 'page' parameter and is accessible to any user with subscriber-level permissions or higher. An attacker can manipulate this parameter to point to arbitrary files stored on the server. If the attacker can upload a file containing malicious PHP code or leverage existing files on the host, they can force the server to execute that code. This vulnerability poses a significant risk to the integrity and confidentiality of the host environment, as it allows for bypass of application-level access controls and potential remote code execution. Defenders should prioritize updating to a patched version or auditing plugin usage to restrict access to the affected functionality.

## Attack Chain

1. Attacker obtains valid subscriber-level credentials for a WordPress site running the vulnerable plugin.
2. Attacker logs into the WordPress dashboard and navigates to the endpoint utilizing the WP Maps plugin.
3. Attacker crafts a malicious HTTP GET or POST request targeting the parameter 'page'.
4. Attacker injects a path traversal or local file path into the 'page' parameter to target a specific file on the server filesystem.
5. The plugin code fails to validate or sanitize the 'page' parameter input.
6. The PHP include function processes the path, triggering the execution of the targeted .php file.
7. Malicious code within the included file executes with the privileges of the web server user.

## Impact

Successful exploitation allows attackers with low-level privileges to gain unauthorized access to sensitive server data, bypass authentication mechanisms, or achieve remote code execution. This can lead to full compromise of the web application and the underlying server environment, depending on the server's configuration and file permissions.

## Recommendation

* Update the WP Maps plugin to the latest version immediately to remediate CVE-2026-13456.
* Audit access logs for suspicious HTTP requests containing directory traversal sequences (e.g., ../) within the 'page' parameter.
* Enforce strict input validation on all plugins to prevent arbitrary file path inclusion.
* Monitor for unexpected file uploads to directories that the web server can read or execute.
