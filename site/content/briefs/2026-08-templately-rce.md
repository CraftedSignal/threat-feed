---
title: Remote Code Execution in Templately WordPress Plugin
slug: 2026-08-templately-rce
description: Authenticated contributors can execute arbitrary code via the Templately plugin by bypassing file type validation through a GIF/PHP polyglot file.
date: "2026-08-15T10:18:16Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Templately
products:
  - Templately – Elementor & Gutenberg Template Library
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Templately – Elementor & Gutenberg Template Library plugin for WordPress is vulnerable to Remote Code Execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: This makes it possible for authenticated attackers, with contributor-level access and above, to execute code on the server.
    confidence_band: high
cves:
  - id: CVE-2026-18438
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18438
rules:
  - title: Detects CVE-2026-18438 Exploitation - Templately API Path Traversal/RCE
    description: Detects unauthorized attempts to access Templately REST API endpoints potentially used for RCE exploitation via image upload.
    platform: sigma
    severity: high
    tactics:
      - execution
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
    - action: Update Templately plugin on all WordPress instances
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-18438 remediation
  hunt_leads:
    - lead: Check web logs for POST requests to Templately endpoints from contributor accounts
      technique_id: T1190
      data_needed:
        - webserver access logs
        - WordPress authentication logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Plugin vulnerable to RCE via API endpoints
  mitigation_plan:
    - priority: immediate
      action: Restrict Templately plugin access to Admin users only
      owner: IT Operations
      addresses: CVE-2026-18438
      evidence: Vulnerability allows contributor access to REST API
---

The Templately - Elementor & Gutenberg Template Library plugin for WordPress (versions 3.7.1 and below) is susceptible to remote code execution (RCE) due to a flaw in the `fetch_remote_file` function. The plugin fails to validate file types against the actual destination path, instead relying on the attacker-controlled Content-Disposition header. An attacker with contributor-level permissions can craft a malicious GIF+PHP polyglot file that bypasses server-side checks. Because the plugin derives the final write path from the request URL, the file is saved with a .php extension rather than the expected image type. Furthermore, Templately's REST API endpoints (including those used for cloud imports) are improperly gated by the `delete_posts` capability, allowing users with low-level privileges to perform sensitive operations. This vulnerability significantly impacts WordPress sites using the plugin by providing a clear path to full system compromise for authenticated users.

## Attack Chain

1. Attacker authenticates to the WordPress site with Contributor-level access or higher.
2. Attacker crafts a GIF/PHP polyglot file designed to bypass `wp_check_filetype_and_ext` validation.
3. Attacker sends a POST request to the vulnerable Templately REST API endpoint, specifically `/templately/v1/clouds/upload`.
4. The request includes a manipulated Content-Disposition header identifying the file as an image/gif to satisfy validation logic.
5. The `fetch_remote_file` function processes the request and writes the payload to the server.
6. Due to the destination path derivation flaw, the file is saved with a .php extension instead of an image extension.
7. Attacker triggers the uploaded PHP file via a direct HTTP request to the web server to achieve remote code execution.

## Impact

Successful exploitation results in unauthorized remote code execution on the underlying web server. This allows an attacker to execute system commands, access the WordPress database, steal sensitive information, or further compromise the hosting environment. Organizations using Templately versions 3.7.1 or older are at risk of complete site takeover by any authenticated user with contributor-level access.

## Recommendation

* Immediately update the Templately plugin to the latest available version to patch the `fetch_remote_file` validation logic.
* Audit WordPress user permissions to identify and restrict excessive contributor-level accounts.
* Deploy the provided web server detection rules to identify malicious requests targeting Templately REST API endpoints.
* Monitor web server logs for suspicious POST requests to `/templately/v1/clouds/upload` that result in unusual file extensions or requests from authenticated accounts with limited roles.
