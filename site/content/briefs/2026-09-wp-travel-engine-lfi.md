---
title: Local File Inclusion Vulnerability in WP Travel Engine Plugin
slug: 2026-09-wp-travel-engine-lfi
description: An unauthenticated-accessible Local File Inclusion vulnerability in the WP Travel Engine plugin (CVE-2026-9231) allows authenticated contributors to achieve remote code execution by including arbitrary PHP files.
date: "2026-09-22T10:35:18Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wp_travel_engine:wp_travel_engine:*:*:*:*:*:wordpress:*:*
tags:
  - web-vulnerability
  - lfi
  - wordpress
vendors:
  - WP Travel Engine
products:
  - WP Travel Engine – Tour Booking Plugin – Tour Operator Software (<= 6.8.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: This makes it possible for authenticated attackers, with contributor-level access and above, to include and execute arbitrary .php files on the server.
    confidence_band: high
cves:
  - id: CVE-2026-9231
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9231
rules:
  - title: Detects CVE-2026-9231 Exploitation - LFI via wte_get_template
    description: Detects potential LFI exploitation attempts against the wte_get_template function in the WP Travel Engine plugin by monitoring for directory traversal patterns.
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
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade WP Travel Engine to the latest patched version.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-9231 vulnerability mitigation
    - action: Deploy Sigma detection rule for LFI patterns targeting wte_get_template.
      owner: Detection Engineering
      due: 48h
      evidence: CVE-2026-9231 exploitation detection
  hunt_leads:
    - lead: Look for unusual PHP file accesses or file inclusions in web server logs originating from low-privilege user accounts.
      technique_id: T1202
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: LFI allows execution of arbitrary .php files
  mitigation_plan:
    - priority: immediate
      action: Patch WP Travel Engine plugin (>= 6.8.1).
      owner: IT Operations
      addresses: CVE-2026-9231
      evidence: Vulnerability fixed in releases following 6.8.0
---

CVE-2026-9231 identifies a critical Local File Inclusion (LFI) vulnerability within the WP Travel Engine - Tour Booking Plugin for WordPress, affecting all versions up to and including 6.8.0. The flaw resides in the wte_get_template function, which fails to adequately sanitize input before using it to include server-side files. An attacker with at least contributor-level privileges can manipulate this function to traverse the directory structure and reference arbitrary .php files stored on the server. If an attacker can successfully upload a file containing malicious PHP code or leverage existing file upload functionality on the WordPress site, they can trigger the inclusion of these files, resulting in remote code execution (RCE). This vulnerability poses a high risk to WordPress installations as it allows for privilege escalation, sensitive data exfiltration, and full server compromise.

## Impact

Successful exploitation of CVE-2026-9231 permits authenticated attackers to execute arbitrary code within the context of the web server process. This can lead to total site takeover, unauthorized access to the WordPress database, exfiltration of sensitive site configuration data, and potentially lateral movement within the hosting environment. Organizations using this plugin for tour booking and operations are at risk if they allow untrusted user accounts (contributors or above) on their WordPress platform.

## Recommendation

1. Upgrade the WP Travel Engine plugin to a version patched against CVE-2026-9231 immediately.
2. Audit user permissions for the WordPress site and remove or demote any accounts with contributor-level or higher access that are not required for business operations.
3. Deploy the Sigma rule below to detect attempts to exploit local file inclusion vulnerabilities targeting the wte_get_template function.
4. Review file upload directories for unauthorized .php files that could serve as payloads for this LFI vulnerability.
