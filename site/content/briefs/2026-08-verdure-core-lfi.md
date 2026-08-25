---
title: Local File Inclusion Vulnerability in Verdure Core WordPress Plugin
slug: 2026-08-verdure-core-lfi
description: An unauthenticated Local File Inclusion vulnerability in Verdure Core versions 1.2 and earlier allows remote attackers to execute arbitrary PHP code on affected WordPress sites.
date: "2026-08-25T10:07:51Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - lfi
  - wordpress
  - vulnerability
  - web-application
vendors:
  - Mikado-Themes
products:
  - Verdure Core (1.2)
cves:
  - id: CVE-2026-78562
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78562
  - https://patchstack.com/database/wordpress/plugin/verdure-core/vulnerability/wordpress-verdure-core-plugin-1-2-local-file-inclusion-vulnerability
rules:
  - title: Detect CVE-2026-78562 Exploitation - Local File Inclusion
    description: Detects potential LFI exploitation attempts against WordPress sites by monitoring for path traversal sequences in common inclusion parameters.
    platform: sigma
    severity: high
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
    - IT Operations
    - SOC
  immediate_actions:
    - action: Audit WordPress environments for Verdure Core plugin version 1.2 or lower
      owner: IT Operations
      due: 24h
      evidence: Source confirms vulnerability exists in versions <= 1.2
    - action: Deploy WAF rules to filter directory traversal strings in URI queries
      owner: SOC
      due: 24h
      evidence: Exploitation relies on LFI via filename parameter manipulation
---

The Verdure Core plugin for WordPress contains a Local File Inclusion (LFI) vulnerability in all versions up to and including 1.2. This vulnerability stems from the improper control of filenames passed to PHP include or require statements (CWE-98). An unauthenticated attacker can manipulate the input parameters processed by the plugin to force the inclusion of arbitrary files present on the server. If an attacker can successfully upload a file containing malicious PHP code - such as an image file containing embedded shell code - they can trigger the execution of this code by including the file via the vulnerable parameter. This flaw allows for remote code execution, sensitive data exposure, and bypass of standard access controls within the WordPress environment. Defenses should focus on immediate patching or disabling the plugin until an update is applied.

## Attack Chain

1. Attacker performs reconnaissance on the target WordPress site to identify the use of the Verdure Core plugin.
2. Attacker crafts a malicious payload, often hidden within a file type allowed by the site (e.g., a manipulated image file or text file containing PHP tags).
3. Attacker uses the site's legitimate file upload functionality to store the payload on the web server.
4. Attacker identifies the parameter used by the Verdure Core plugin that handles file inclusion.
5. Attacker sends a crafted HTTP request to the vulnerable endpoint, setting the inclusion parameter to point to the previously uploaded malicious file path.
6. The web server process interprets the included file as PHP, executing the embedded malicious commands.
7. Attacker gains a webshell or executes arbitrary system-level commands with the privileges of the web server user.

## Impact

Successful exploitation of this vulnerability allows unauthenticated remote attackers to execute arbitrary PHP code on the underlying web server. This can lead to full site compromise, exfiltration of sensitive database information (such as wp-config.php containing database credentials), or the establishment of persistent backdoors. As a widely used framework, WordPress sites are frequent targets for such automated LFI exploitation campaigns, potentially resulting in unauthorized administrative access or the use of the server as a pivot point for further network movement.

## Recommendation

- Immediately update the Verdure Core plugin to the latest available version that patches this vulnerability.
- If a patch is unavailable, deactivate or remove the Verdure Core plugin from all WordPress instances.
- Implement Web Application Firewall (WAF) rules to inspect and block HTTP requests containing path traversal sequences (e.g., ../, ..%2f) or suspicious file extensions in parameters targeted by the plugin.
- Enable detailed web server access logging and monitor for anomalous HTTP requests targeting files in uploads directories that coincide with suspicious status codes or unusual query strings.
- Deploy the Sigma rule below to detect attempts to exploit LFI via webserver log telemetry.
