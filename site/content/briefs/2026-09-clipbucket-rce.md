---
title: Remote Code Execution in ClipBucket via Unrestricted File Upload
slug: 2026-09-clipbucket-rce
description: Authenticated users can exploit a file upload vulnerability in ClipBucket v5 before 5.5.3-#182 to achieve remote code execution by bypassing MIME validation.
date: "2026-09-18T16:07:59Z"
lastmod: "2026-09-23T02:40:38Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:clipbucket:clipbucket:*:*:*:*:*:*:*:*
tags:
  - cve-2026-77929
  - remote-code-execution
  - file-upload
  - clipbucket
  - cve-2026-96272
  - sqli
  - web-vulnerability
vendors:
  - ClipBucket
products:
  - ClipBucket (< 5.5.3-#182)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An authenticated attacker can bypass MIME validation by providing a PHP file with valid image magic bytes.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can exploit time-based blind SQL injection techniques to extract user credentials, email addresses, and administrator password hashes for account takeover.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can exploit time-based blind SQL injection techniques to extract user credentials, email addresses, and administrator password hashes for account takeover.
    confidence_band: high
cves:
  - id: CVE-2026-77929
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77929
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96272
rules:
  - title: Detect CVE-2026-77929 Exploitation - Suspicious File Upload
    description: Detects potential exploitation attempts of CVE-2026-77929 by monitoring for PHP files being accessed within the upload directory structure.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
  - title: Detects CVE-2026-96272 Exploitation - Blind SQL Injection in Photo Search
    description: Detects potential blind SQL injection attempts by identifying time-delay or boolean-based SQL keywords in the query parameter of the photo search endpoint.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch all instances of ClipBucket to 5.5.3-#182 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-77929 remediation
  mitigation_plan:
    - priority: immediate
      action: Disable PHP execution in the uploads directory
      owner: IT Operations
      addresses: CVE-2026-77929
      evidence: Mitigate file upload RCE vector
updates:
  - at: "2026-09-23T02:40:38Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-96272 Exploitation - Blind SQL Injection in Photo Search'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-96272
---

ClipBucket v5 versions prior to 5.5.3-#182 are susceptible to a critical remote code execution (RCE) vulnerability. The flaw exists within the FileUpload::manageFile() function located in fileupload.class.php. Attackers with valid application accounts can bypass the existing MIME type validation by crafting a malicious PHP payload that includes valid image magic bytes. Because the application logic fails to correctly enforce or update the file extension during the processing phase, the server saves the attacker-supplied file with a .php extension to the web-accessible filesystem. Once uploaded, an attacker can trigger the execution of this file via PHP-FPM by navigating to the file path, resulting in arbitrary code execution on the underlying host. This vulnerability represents a significant risk for organizations running ClipBucket in internet-facing configurations, as it allows full system compromise upon successful authentication and upload.

## Attack Chain

1. Attacker authenticates to the ClipBucket application as a registered user.
2. Attacker crafts a PHP payload disguised as an image by prepending valid image magic bytes to the file content.
3. Attacker initiates a photo upload request to the application's photo upload endpoint.
4. The application triggers FileUpload::manageFile() to validate the uploaded file's MIME type.
5. The validation logic is bypassed by the presence of the legitimate image magic bytes.
6. The application writes the malicious file to the storage directory, failing to sanitize or overwrite the .php extension.
7. Attacker identifies the storage path of the uploaded file via the application response or web directory enumeration.
8. Attacker sends an HTTP request to the uploaded file's URL, causing the web server to execute the PHP code via PHP-FPM.

## Impact

Successful exploitation of this vulnerability allows an authenticated attacker to execute arbitrary code on the web server with the privileges of the web service account. This could lead to full system compromise, data theft, further lateral movement within the network, or the installation of persistent backdoors. Targeted entities include any organization hosting video content platforms using vulnerable versions of ClipBucket.

## Recommendation

Prioritized actions for defense and remediation:
- Patch ClipBucket to version 5.5.3-#182 or later immediately to resolve the logic error in FileUpload::manageFile().
- Inspect web server access logs for repeated HTTP 200 responses to files with extensions like .php residing in typical user-upload directories.
- Implement strict file extension whitelisting on all web application upload endpoints to ensure only non-executable formats are processed.
- Configure the web server and PHP-FPM to prevent script execution within directories intended for user-provided static content (e.g., /uploads/).
- Deploy web application firewall (WAF) rules to detect and block file upload requests containing suspicious PHP code sequences within image-based MIME payloads.
