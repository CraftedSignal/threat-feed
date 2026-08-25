---
title: Arbitrary File Upload in CM Map Locations WordPress Plugin
slug: 2026-08-cm-map-locations-rce
description: The CM Map Locations WordPress plugin is vulnerable to remote code execution due to insufficient file validation in the uploadMedia function, allowing subscriber-level authenticated users to upload arbitrary executable files.
date: "2026-08-25T10:07:27Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - arbitrary-file-upload
  - remote-code-execution
  - plugin-vulnerability
vendors:
  - CreativeMinds
products:
  - CM Map Locations (2.1.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The CM Map Locations ... plugin for WordPress is vulnerable to Limited Arbitrary File Upload ... via the uploadMedia function.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505.003
    technique_name: 'Server Software Component: Web Shell'
    evidence: This makes it possible for authenticated attackers ... to upload files that may be executable, which makes remote code execution possible.
    confidence_band: high
cves:
  - id: CVE-2026-16601
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16601
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update CM Map Locations to version > 2.1.8
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-16601 advisory
  mitigation_plan:
    - priority: immediate
      action: Monitor webserver logs for unauthorized POST requests to plugin directories
      owner: SOC
      addresses: CVE-2026-16601
      evidence: Vulnerability allows arbitrary file upload via web upload handler
---

The CM Map Locations plugin for WordPress (up to version 2.1.8) contains a critical security flaw involving the improper handling of file uploads in the uploadMedia function. The plugin fails to perform adequate file type validation or MIME-type checking, allowing authenticated users with subscriber-level access to bypass extension filtering. 

The vulnerability is exacerbated by the exposure of a required security nonce within the CMLOC_Editor_Images JavaScript object on the front-end location editor page. By obtaining this nonce, an authenticated subscriber can craft requests that bypass intended permission checks, leading to the upload of executable files to the server. Successful exploitation allows for remote code execution, posing a significant risk to site integrity and server security. Defenders should prioritize updating to the patched version of the plugin and auditing logs for unusual file uploads to the plugin media directories.

## Attack Chain

1. Attacker authenticates as a user with subscriber-level privileges on the WordPress site.
2. Attacker navigates to the front-end location editor page provided by the CM Map Locations plugin.
3. Attacker extracts the required security nonce from the CMLOC_Editor_Images JavaScript object.
4. Attacker crafts a POST request to the uploadMedia handler using the extracted nonce.
5. Attacker includes a malicious payload (e.g., a PHP script) within the file upload request.
6. The plugin fails to validate the file extension or MIME-type, passing the file to move_uploaded_file().
7. The malicious file is written to the web-accessible file system.
8. Attacker requests the uploaded file directly via the browser to trigger remote code execution.

## Impact

Successful exploitation of this vulnerability allows an unprivileged authenticated user to gain remote code execution on the WordPress server. This could lead to full site compromise, exfiltration of database contents, or use of the host server for further network attacks. Because the plugin is a common mapping solution, the potential blast radius includes any WordPress instance running version 2.1.8 or lower.

## Recommendation

- Update the CM Map Locations plugin to the latest version immediately to remediate the vulnerable uploadMedia function.
- Audit the webserver access logs for anomalous POST requests to the plugin upload endpoints, specifically targeting non-image file extensions or suspicious file paths.
- Review WordPress user roles to ensure that subscriber accounts are necessary and do not have access to sensitive front-end editing features where these scripts are exposed.
- Implement file integrity monitoring on the WordPress uploads directory to detect unauthorized file creation by the web service user.
