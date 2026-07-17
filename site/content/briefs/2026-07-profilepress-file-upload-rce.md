---
title: Arbitrary File Upload Vulnerability in ProfilePress WordPress Plugin (CVE-2026-13352)
slug: 2026-07-profilepress-file-upload-rce
description: An arbitrary file upload vulnerability, CVE-2026-13352, affects the ProfilePress plugin for WordPress up to version 4.16.18, allowing authenticated attackers with author-level privileges or higher to upload executable files, which can lead to remote code execution.
date: "2026-07-17T05:18:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - vulnerability
  - rce
  - file-upload
  - cms
vendors:
  - ProfilePress
products:
  - ProfilePress plugin for WordPress
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: authenticated attackers, with author-level access and above
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: which makes remote code execution possible
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1609
    technique_name: Web Compromise
    evidence: upload files that may be executable, which makes remote code execution possible.
    confidence_band: high
cves:
  - id: CVE-2026-13352
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13352
---

A critical arbitrary file upload vulnerability, identified as CVE-2026-13352, has been discovered in the ProfilePress plugin for WordPress, impacting all versions up to and including 4.16.18. This flaw arises from an unconditionally registered filter that expands the global WordPress MIME allowlist to include executable file extensions such as `.exe`, `.apk`, and `.msi`. This expansion is applied site-wide, regardless of whether the digital products feature that introduced the filter is configured or in use. Consequently, authenticated attackers possessing author-level access or higher can exploit this vulnerability to upload malicious executable files. Successful exploitation enables remote code execution on the compromised WordPress instance, allowing attackers to potentially gain full control over the affected website and underlying server. This poses a significant risk for organizations using the ProfilePress plugin.

## Attack Chain

1. **Initial Access**: An attacker gains authenticated access to the WordPress site with at least author-level privileges, either through stolen credentials or by registering an account if open registration is enabled.
2. **Vulnerability Exploitation**: The authenticated attacker crafts a malicious executable file (e.g., a reverse shell, web shell, or other malware) with an extension like `.exe`, `.apk`, or `.msi`.
3. **File Upload**: The attacker uploads the malicious file via the WordPress media uploader or any ProfilePress-specific upload function that leverages the globally expanded MIME allowlist.
4. **File Placement**: The uploaded executable file is stored on the web server's file system, typically within the `wp-content/uploads/` directory or a plugin-specific subdirectory.
5. **Remote Code Execution Trigger**: The attacker accesses or triggers the execution of the uploaded malicious file through a web request or another method, leveraging the web server's ability to execute the now allowed executable file type.
6. **Impact Realization**: The malicious executable code runs on the server, leading to remote code execution, which can result in full server compromise, data exfiltration, website defacement, or further lateral movement within the network.

## Impact

The successful exploitation of CVE-2026-13352 can lead to severe consequences for affected WordPress sites. Attackers can achieve remote code execution, granting them the ability to take full control of the web server. This includes unauthorized access to sensitive data, modification or deletion of website content, installation of backdoors or other malware, and potentially using the compromised server as a pivot point for further attacks on the internal network. The wide use of WordPress and the ProfilePress plugin means that a large number of websites could be vulnerable to data breaches, service disruption, and reputation damage if not patched promptly.

## Recommendation

* Patch CVE-2026-13352 immediately by updating the ProfilePress plugin to a version greater than 4.16.18.
* Review web server access logs for any unusual file uploads, particularly those with `.exe`, `.apk`, or `.msi` extensions to common WordPress upload directories.
* Ensure that all WordPress user accounts, especially those with author-level or higher privileges, adhere to strong password policies and are monitored for suspicious activity.
