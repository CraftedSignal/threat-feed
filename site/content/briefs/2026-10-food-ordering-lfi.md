---
title: Local File Inclusion Vulnerability in Food-Ordering 1.0
slug: 2026-10-food-ordering-lfi
description: Food-Ordering 1.0 contains a Local File Inclusion (LFI) vulnerability in update_category.php allowing authenticated users to upload and execute arbitrary files via the update_image parameter.
date: "2026-10-01T15:12:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - lfi
  - web-vulnerability
  - remote-code-execution
vendors:
  - Kato James Kalemba
products:
  - Food-Ordering (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated user can manipulate this parameter, it can lead to directory traversal, unauthorized access to sensitive files, or full server compromise.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attacker includes the malicious script content within the body of the 'update_image' form field.
    confidence_band: high
references:
  - https://www.exploit-db.com/exploits/52689
  - https://github.com/nu11secur1ty/CVE-nu11secur1ty/tree/main/2026/Food-Ordering-1.0-kato-james-kalemba
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review access logs for POST requests to /web/admin/update_category.php
      owner: SOC
      due: 24h
      evidence: Exploit documentation identifies this specific endpoint as the vector
  mitigation_plan:
    - priority: immediate
      action: Block access to the administrative directory or restrict to internal networks
      owner: IT Operations
      addresses: Food-Ordering 1.0
      evidence: Exploit provides a clear path to server compromise
---

Food-Ordering version 1.0 contains a Local File Inclusion (LFI) vulnerability stemming from improper input sanitization within the application's file-handling functions. The vulnerability exists in the update_category.php script, specifically affecting the processing of the 'update_image' parameter. An authenticated attacker can exploit this flaw by submitting a crafted HTTP POST request that substitutes a legitimate image file with a malicious script (e.g., a PHP shell). Because the application fails to validate the filename or content type of the uploaded file, the attacker can force the server to accept and subsequently execute the malicious file. This vulnerability enables directory traversal, unauthorized access to sensitive server-side configuration files, and potential full system compromise. The vulnerability was disclosed via Exploit-DB (EDB-52689) on October 1, 2026, and provides a clear mechanism for remote code execution.

## Attack Chain

1. Attacker obtains valid session credentials for the administrative interface of the Food-Ordering application.
2. Attacker navigates to the administrative category update function at /web/admin/update_category.php.
3. Attacker crafts a multipart/form-data POST request targeting the 'update_image' field.
4. Attacker modifies the 'filename' parameter in the form data to point to a malicious script, such as 'info.php'.
5. Attacker includes the malicious script content within the body of the 'update_image' form field.
6. Server-side application processes the upload request without verifying the file extension or MIME type.
7. Malicious script is written to the web-accessible directory on the server.
8. Attacker requests the newly uploaded file directly via the browser to trigger execution and achieve remote code execution.

## Impact

Successful exploitation of this vulnerability allows an authenticated attacker to execute arbitrary code on the underlying web server. This can result in complete loss of confidentiality, integrity, and availability of the web application data, as well as the potential for lateral movement within the network if the server is improperly segmented.

## Recommendation

Prioritize the immediate restriction of administrative interface access to trusted networks only. Disable the file upload functionality in update_category.php until a security patch can be applied by the developer. Implement strict server-side validation for all file uploads, ensuring that only expected image file extensions and content types are accepted. Ensure the web application directory is configured to prevent the execution of scripts in upload folders.

## Rules

- title: "Detect Exploitation of Food-Ordering LFI"
 description: "Detects potential LFI or file upload exploitation attempts targeting update_category.php by monitoring for suspicious file extensions in POST requests"
 logsource:
 category: "webserver"
 detection:
 selection:
 cs-method: "POST"
 cs-uri-stem|contains: "/web/admin/update_category.php"
 cs-multipart-filename|endswith:
 - ".php"
 - ".php5"
 - ".phtml"
 - ".jsp"
 - ".asp"
 condition: selection
 level: "high"
 tags:
 - "attack.initial_access"
 - "attack.t1190"
 falsepositives:
 - "Legitimate administrative uploads if the application is intended to support script hosting, which is non-standard"
 tests:
 positive:
 - name: "POST request with PHP file upload"
 data:
 - cs-method: "POST"
 cs-uri-stem: "/web/admin/update_category.php"
 cs-multipart-filename: "shell.php"
 negative:
 - name: "POST request with valid image upload"
 data:
 - cs-method: "POST"
 cs-uri-stem: "/web/admin/update_category.php"
 cs-multipart-filename: "category_image.jpg"
 handoff:
 detection_confidence: "high"
 required_telemetry:
 - log_source: "Web Server Access/Error Logs"
 event_or_channel: "HTTP POST request"
 required_fields:
 - "cs-method"
 - "cs-uri-stem"
 - "cs-multipart-filename"
 availability: "available"
 notes: "Requires WAF or Web Server logs capable of parsing multipart/form-data filenames"
 validation:
 status: "needs_environment_validation"
 steps:
 - "Send a legitimate-looking POST request to the update_category.php endpoint with a benign .php file"
 expected_telemetry: "Detection rule should trigger"
 pass_criteria: "Rule match on the target URI and forbidden filename extension"
 known_evasions:
 - "Using double extensions like .jpg.php if not explicitly blocked"
 limitations:
 - "Will not detect if the server renames the uploaded file to a random string"
 tuning:
 - source: "WAF logs"
 guidance: "Monitor for unexpected content types in multipart upload fields"
 portability_notes:
 - platform: "Splunk|Elastic"
 note: "Ensure field extraction for multipart filenames is configured"
 suggested_owner: "Detection Engineering"
