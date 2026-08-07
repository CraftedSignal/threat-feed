---
title: CodeIgniter4 Unsafe File Upload Validation Bypass
slug: 2026-08-codeigniter-upload-bypass
description: CodeIgniter4 versions before 4.7.4 contain an unsafe file upload validation bypass in 'is_image' and 'mime_in' rules, allowing attackers to upload arbitrary files that could result in remote code execution.
date: "2026-08-07T21:30:48Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - web-application
  - file-upload
  - cve-2026-63223
vendors:
  - CodeIgniter
products:
  - CodeIgniter4
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This is an unsafe file upload validation vulnerability that can lead to remote code execution in vulnerable application configurations.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505.003
    technique_name: 'Server Software Component: Web Shell'
    evidence: An attacker can upload and execute arbitrary malicious PHP scripts, resulting in remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-63223
    cvss: 9.8
    epss: 0.00493
references:
  - https://github.com/advisories/GHSA-mmj4-63m4-r6h5
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Audit CodeIgniter4 dependency versions and upgrade to v4.7.4
      owner: IT Operations
      due: 24h
      evidence: Upgrade to v4.7.4 or later.
  mitigation_plan:
    - priority: immediate
      action: Configure web server to disable PHP execution in upload directories
      owner: IT Operations
      addresses: CVE-2026-63223
      evidence: Disable script execution in any public upload directory.
---

CodeIgniter4, a popular open-source PHP web framework, contains a critical vulnerability tracked as CVE-2026-63223. The flaw resides in the framework's file upload validation logic, specifically within the 'is_image' and 'mime_in' validation rules. An attacker can manipulate file uploads to bypass intended extension restrictions if the application relies solely on these rules without additional, independent verification of the file extension. If a web application saves these uploaded files using the client-supplied filename and stores them in a directory where server-side script execution is enabled, an attacker can upload and execute arbitrary malicious PHP scripts, resulting in remote code execution (RCE). The vulnerability affects all versions of the CodeIgniter4 framework prior to v4.7.4.

## Impact

Successful exploitation allows for arbitrary file upload and remote code execution on the underlying web server. This poses a severe risk to any application that allows user-submitted file uploads and fails to decouple validation rules from filename storage or directory execution permissions. Impacted organizations are urged to upgrade to v4.7.4 or implement strict storage and execution policies.

## Recommendation

* Upgrade all instances of CodeIgniter4 to v4.7.4 or later immediately.
* Ensure that uploaded files are saved in directories outside the public web root, such as 'writable/uploads', to prevent direct execution.
* When saving files, avoid using the client-supplied original filename; use methods like '$file->getRandomName()' to randomize the destination filename.
* Configure the web server to disable script execution (e.g., PHP parsing) within any public-facing upload directories.
* Implement defense-in-depth by manually verifying that the client extension matches the guessed MIME type before finalizing the file move.
