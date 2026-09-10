---
title: Unauthenticated Remote Code Execution in Drag and Drop File Upload for Elementor Forms
slug: 2026-09-drag-and-drop-file-upload-rce
description: An arbitrary file upload vulnerability in the Drag and Drop File Upload for Elementor Forms WordPress plugin allows unauthenticated attackers to execute arbitrary code via MIME type validation bypass.
date: "2026-09-10T03:03:37Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:drag_and_drop_file_upload_for_elementor_forms_project:drag_and_drop_file_upload_for_elementor_forms:*:*:*:*:*:wordpress:*:*
tags:
  - vulnerability
  - rce
  - wordpress
  - web-application
vendors:
  - WordPress
products:
  - Drag and Drop File Upload for Elementor Forms (<= 1.6.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to upload files that may be executable, which makes remote code execution possible.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The Drag and Drop File Upload for Elementor Forms plugin for WordPress is vulnerable to Arbitrary File Upload... which makes remote code execution possible.
    confidence_band: high
cves:
  - id: CVE-2026-18351
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18351
rules:
  - title: Detects CVE-2026-18351 Exploitation - Arbitrary File Upload via Elementor Forms Plugin
    description: Detects suspicious POST requests to the elementor_file_upload endpoint involving file uploads
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
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Drag and Drop File Upload for Elementor Forms plugin to version 1.6.1 or later
      owner: IT Operations
      due: 24h
      evidence: Plugin is vulnerable in all versions up to, and including, 1.6.0
  hunt_leads:
    - lead: Search web logs for POST requests to plugin upload endpoints with non-standard file extensions
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows arbitrary file upload via elementor_file_upload function
  mitigation_plan:
    - priority: immediate
      action: Upgrade plugin to version 1.6.1+
      owner: IT Operations
      addresses: CVE-2026-18351
      evidence: Source states versions up to 1.6.0 are vulnerable
---

The Drag and Drop File Upload for Elementor Forms WordPress plugin, version 1.6.0 and earlier, contains a critical arbitrary file upload vulnerability tracked as CVE-2026-18351. The vulnerability exists within the 'is_file_type_valid()' function, which improperly handles the 'type' parameter during file uploads. Specifically, the function uses this attacker-controlled parameter as a regex key when checking against MIME type allowlists. By crafting a request that influences this logic, an unauthenticated attacker can bypass existing file type restrictions. The 'sanitize_file_name()' function subsequently normalizes the filename, potentially converting a manipulated input into a executable PHP script. If successfully exploited, this flaw allows for unauthenticated remote code execution on the underlying WordPress server. Defenders should identify instances of this plugin in their environment and ensure they are patched beyond version 1.6.0.

## Attack Chain

1. Attacker performs reconnaissance to identify sites running the vulnerable Drag and Drop File Upload for Elementor Forms plugin.
2. Attacker crafts an HTTP POST request targeting the 'elementor_file_upload' function endpoint.
3. Attacker injects a malicious payload into the 'type' parameter to subvert the 'is_file_type_valid()' regex validation logic.
4. Attacker uploads a file with a double extension or normalized name that bypasses the MIME type allowlist.
5. The plugin's 'sanitize_file_name()' function normalizes the malicious filename into an executable PHP file.
6. The web server saves the attacker-supplied PHP file to a publicly accessible directory.
7. Attacker requests the uploaded PHP file via the web browser to trigger remote code execution.

## Impact

Successful exploitation of CVE-2026-18351 enables unauthenticated remote code execution. This can lead to full site compromise, data exfiltration, installation of webshells for persistence, and further lateral movement within the hosting infrastructure.

## Recommendation

1. Immediately update the Drag and Drop File Upload for Elementor Forms plugin to the latest available version beyond 1.6.0.
2. Audit web server logs for HTTP POST requests to the 'elementor_file_upload' endpoint containing irregular 'type' parameters or attempts to upload .php, .phtml, or .php5 files.
3. Implement Web Application Firewall (WAF) rules to inspect and block requests containing suspicious MIME type strings or file upload attempts from unauthorized or non-standard sources.
4. Use file integrity monitoring to detect the creation of new, unexpected files in plugin-associated upload directories.
