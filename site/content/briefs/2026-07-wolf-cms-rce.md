---
title: Authenticated Remote Code Execution in Wolf CMS
slug: 2026-07-wolf-cms-rce
description: Wolf CMS versions up to 0.8.3.1 contain a remote code execution vulnerability in the FileManagerController allowing authenticated users with specific permissions to upload and execute arbitrary PHP files.
date: "2026-07-30T21:31:53Z"
lastmod: "2026-09-01T14:31:23Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wolf_cms:wolf_cms:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://www.exploit-db.com/exploits/52672
tags:
  - remote-code-execution
  - web-application-vulnerability
vendors:
  - Wolf CMS
products:
  - Wolf CMS (<= 0.8.3.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Wolf CMS through 0.8.3.1 contains a remote code execution vulnerability in FileManagerController that allows authenticated attackers to create arbitrary PHP files
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attackers with the file_manager_mkfile capability can write malicious PHP content into the web-accessible FILES_DIR directory and trigger execution
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Wolf CMS through 0.8.3.1 contains an authorization bypass vulnerability in BackupRestoreController that allows authenticated non-administrative users to access restricted backup functionality
    confidence_band: high
cves:
  - id: CVE-2026-67206
    cvss: 8.8
    epss: 0.00577
  - id: CVE-2026-67207
    cvss: 8.8
    epss: 0.003
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67206
  - https://github.com/Caycon/cve-advisories/blob/main/2026/WolfCms/CVE-2026-67206.md
  - https://www.vulncheck.com/advisories/wolf-cms-authenticated-rce-via-filemanagercontroller-file-upload
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67207
  - https://www.vulncheck.com/advisories/wolf-cms-authorization-bypass-via-backuprestorecontroller
  - https://github.com/Caycon/cve-advisories/blob/main/2026/WolfCms/CVE-2026-67207.md
  - https://www.exploit-db.com/exploits/52672
rules:
  - title: Detects CVE-2026-67206 Exploitation - File Upload to FileManagerController
    description: Detects potential exploitation of CVE-2026-67206 by monitoring HTTP POST requests to the File Manager module's creation functions.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-07-30T21:32:01Z"
    level: L2
    summary: 'merged source coverage: Authorization Bypass in Wolf CMS BackupRestoreController'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-67207
  - at: "2026-09-01T14:31:23Z"
    level: L2
    summary: poc_available; added CVE-2026-67206 +1
    sources:
      - exploit-db
    source_urls:
      - https://www.exploit-db.com/exploits/52672
---

Wolf CMS versions 0.8.3.1 and earlier contain a critical remote code execution (RCE) vulnerability (CVE-2026-67206) residing within the `FileManagerController`. The vulnerability stems from improper validation of file extensions in the `create_file()` and `save()` functions. An attacker who has authenticated to the CMS and possesses the `file_manager_mkfile` capability can exploit this flaw to create and upload arbitrary PHP files into the web-accessible `FILES_DIR` directory. Once the file is uploaded, an attacker can trigger remote code execution by sending an HTTP request directly to the newly created file. This vulnerability poses a significant risk to organizations using Wolf CMS, as it effectively elevates the access of a standard CMS user to full system code execution.

## Attack Chain

1. Attacker authenticates to the Wolf CMS administrative interface using valid, potentially compromised, credentials.
2. Attacker verifies they possess the `file_manager_mkfile` capability within the application.
3. Attacker navigates to the File Manager module within the administrative dashboard.
4. Attacker invokes the `create_file()` or `save()` function to create a new file, providing a malicious payload formatted as PHP code.
5. Attacker bypasses the missing server-side extension validation, ensuring the file is saved with a `.php` extension in the `FILES_DIR` directory.
6. Application writes the attacker-supplied PHP content to the server disk at the specified path.
7. Attacker triggers the execution of the malicious script by navigating to the file path via a standard browser HTTP request.
8. Web server executes the PHP payload, resulting in remote code execution under the context of the web server user.

## Impact

Successful exploitation of this vulnerability allows an authenticated attacker to achieve remote code execution on the underlying web server. This can lead to full compromise of the web application, potential lateral movement within the hosting environment, and exfiltration of sensitive configuration or database information. Given the nature of the application, this flaw is particularly dangerous for small-to-medium organizations relying on Wolf CMS for content management.

## Recommendation

1. Immediately audit user roles and capabilities in Wolf CMS to identify accounts with the `file_manager_mkfile` privilege; restrict this access to trusted administrators only.
2. Monitor web server logs for suspicious requests to files created within the `FILES_DIR` path, particularly those ending in `.php`.
3. Deploy the provided Sigma rule to detect POST requests to the `FileManagerController` that coincide with file creation events.
4. Review the Wolf CMS GitHub repository for updates and patch to a version beyond 0.8.3.1 immediately once available.
