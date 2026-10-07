---
title: Unauthenticated RCE in Hash Form Plugin for WordPress
slug: 2026-10-hash-form-rce
description: An unauthenticated arbitrary file upload vulnerability (CVE-2026-81780) in the Hash Form WordPress plugin allows attackers to achieve remote code execution through the 'admin-ajax.php' endpoint.
date: "2026-10-07T13:41:30Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:hash_form:hash_form:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - arbitrary-file-upload
  - rce
  - webserver
vendors:
  - Hash Form
products:
  - Hash Form (<= 1.4.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: CVE-2026-81780 is a vulnerability in the Hash Form plugin allowing unauthenticated arbitrary file upload.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The attacker uploads and executes PHP shells to achieve RCE.
    confidence_band: high
cves:
  - id: CVE-2026-81780
    cvss: 10
    epss: 0.00522
references:
  - https://sploitus.com/exploit?id=83CE531F-329D-556A-8A17-1ADD895EA13A
rules:
  - title: Detects CVE-2026-81780 Exploitation - Hash Form Arbitrary File Upload
    description: Detects exploitation attempts against the Hash Form plugin via the admin-ajax.php endpoint to upload arbitrary files.
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
    - action: Block access to /wp-admin/admin-ajax.php?action=hashform_file_upload_action at the WAF level.
      owner: SOC
      due: 2h
      evidence: Plugin requires this endpoint for the vulnerability; blocking stops the attack vector.
  mitigation_plan:
    - priority: immediate
      action: Update Hash Form plugin to version 1.4.3 or higher.
      owner: IT Operations
      addresses: CVE-2026-81780
      evidence: Source explicitly identifies version 1.4.2 as the last vulnerable version.
---

Hash Form, a WordPress plugin, contains a critical vulnerability (CVE-2026-81780) that allows unauthenticated attackers to upload arbitrary files to the server. The vulnerability resides in the `hashform_file_upload_action` action handled by the `admin-ajax.php` file. By manipulating the `allowedExtensions[]` parameter, an attacker can bypass file extension validation, enabling the upload of malicious PHP files into public-facing directories.

Publicly available exploits for this vulnerability are actively circulating as of October 2026. These exploits automate the scanning process, support multiple PHP-executable extensions (such as .php7, .pht, and .phar), and include advanced techniques to override server configurations via .htaccess if direct execution is blocked. Successful exploitation grants attackers remote code execution capabilities, allowing them to issue commands via the uploaded file. This vulnerability affects Hash Form versions 1.4.2 and earlier.

## Attack Chain

1. The attacker sends a GET request to `/wp-admin/admin-ajax.php?action=hashform_preview` to extract the required `ajax_nounce` parameter.
2. The attacker crafts a POST request to `/wp-admin/admin-ajax.php?action=hashform_file_upload_action` containing the `file_uploader_nonce`.
3. The attacker sets the `allowedExtensions[]` parameter to an arbitrary value to bypass the plugin's validation logic.
4. The attacker uploads a malicious PHP shell file using the `qqfile` parameter within the POST body.
5. If the server prevents direct PHP execution, the attacker attempts to upload an .htaccess file to override server handlers.
6. The attacker verifies the RCE by sending an HTTP GET request to the uploaded shell file with a command parameter (e.g., `?c=id`).
7. The attacker executes arbitrary system commands via the uploaded shell, leading to full server compromise.

## Impact

Successful exploitation of CVE-2026-81780 leads to unauthenticated remote code execution on the WordPress server. This allows for complete data exfiltration, total site takeover, and potential lateral movement into the hosting infrastructure. Multiple public exploit scripts exist, significantly increasing the likelihood of widespread automated exploitation of vulnerable WordPress sites.

## Recommendation

Prioritize patching all affected instances immediately.

* Update the Hash Form plugin to version 1.4.3 or later.
* If immediate patching is not possible, disable the Hash Form plugin entirely.
* Deploy a WAF rule to block requests to `admin-ajax.php` where `action=hashform_file_upload_action` if the request originates from untrusted sources.
* Restrict execution permissions in the `wp-content/uploads/hashform/` directory via server configuration (e.g., `.htaccess` or Nginx `location` blocks).
* Use the provided Sigma rule to detect attempts to invoke the vulnerable plugin action.
