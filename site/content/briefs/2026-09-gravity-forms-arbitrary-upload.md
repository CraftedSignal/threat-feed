---
title: Arbitrary File Upload Vulnerability in Gravity Forms
slug: 2026-09-gravity-forms-arbitrary-upload
description: An arbitrary file upload vulnerability in the Gravity Forms WordPress plugin (<= 3.0.2) allows unauthenticated attackers to write arbitrary files to the temporary upload directory, potentially leading to remote code execution or stored XSS.
date: "2026-09-01T15:07:06Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gravity_forms:gravity_forms:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - vulnerability
  - rce
  - xss
vendors:
  - Gravity Forms
products:
  - Gravity Forms (<= 3.0.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can upload malicious files, including PHP scripts, to the plugin's temporary upload directory.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This can lead to remote code execution on WordPress systems that use NGINX or other non .htaccess respecting web servers.
    confidence_band: high
cves:
  - id: CVE-2026-19513
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19513
rules:
  - title: Detect Potential Gravity Forms Arbitrary File Upload Attempt
    description: Detects unauthorized attempts to write files with executable extensions via the Gravity Forms upload handler, targeting CVE-2026-19513.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
      - T1203
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch Gravity Forms to version 3.0.3 or higher
      owner: IT Operations
      due: 24h
      evidence: Plugin version 3.0.2 and below is confirmed vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Verify presence of .htaccess file in the Gravity Forms temporary directory
      owner: Security Operations
      addresses: CVE-2026-19513
      evidence: The source notes that .htaccess files are used to block exploitation.
---

Gravity Forms versions up to and including 3.0.2 contain a critical vulnerability in the `GFAsyncUpload::upload()` function. The flaw stems from insufficient validation of multi-file upload chunk state, allowing the reuse of public form state URL hashes as chunk continuation hashes. Attackers can leverage this to influence the temporary filename used during the upload process. 

When a public-facing form includes a File Upload field with the "Multiple Files" option enabled, an unauthenticated attacker can upload files to the plugin's temporary storage directory. On web servers that do not honor `.htaccess` files (e.g., NGINX), this allows for the upload of executable PHP code, resulting in remote code execution. In environments where the plugin successfully places a `.htaccess` file to block PHP execution, the vulnerability still allows for stored cross-site scripting (XSS) if an attacker uploads malicious HTML files that are subsequently accessed by users.

## Attack Chain

1. Attacker identifies a WordPress site running a vulnerable version of Gravity Forms (<= 3.0.2).
2. Attacker discovers a public form containing a File Upload field with "Multiple Files" enabled.
3. Attacker crafts a malicious payload (e.g., PHP polyglot or malicious HTML).
4. Attacker performs a multipart file upload request to the `GFAsyncUpload::upload()` endpoint.
5. Attacker manipulates the chunk continuation hash to control the destination filename in the temporary upload directory.
6. Server processes the request and writes the malicious file to the storage directory.
7. Attacker navigates to the file URL to trigger execution (RCE) or XSS.

## Impact

Successful exploitation can lead to full remote code execution on the underlying server if it does not properly restrict execution in the temporary directory. In secondary scenarios, attackers can achieve stored XSS, allowing for session hijacking or further compromise of authenticated administrative users.

## Recommendation

Prioritized actions for the detection engineering and security operations teams:

- Upgrade the Gravity Forms plugin to the latest patched version immediately.
- Implement a web application firewall (WAF) rule to block POST requests to Gravity Forms upload endpoints that contain suspicious filename extensions (e.g., .php, .html, .js) if upgrading is delayed.
- Audit the temporary upload directory for unauthorized files, particularly those with executable extensions.
- Ensure the web server configuration explicitly denies execution of files in the Gravity Forms temporary upload directory.
