---
title: Grav API Plugin File Upload Extension Bypass Leading to RCE
slug: 2026-07-grav-api-rce-bypass
description: A vulnerability (CVE-2026-61457) in the Grav API plugin before version 1.0.3 allows an authenticated attacker with `api.media.write` permissions to bypass file upload extension validation using double extensions, which can lead to remote code execution on the web server.
date: "2026-07-15T12:35:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - remote-code-execution
  - extension-bypass
  - grav
vendors:
  - Grav
products:
  - Grav API plugin (getgrav/grav-plugin-api) < 1.0.3
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A vulnerability in the Grav API plugin...allows attackers ... to bypass file upload extension validation.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: ""
    evidence: upload a file with a double extension such as shell.php.jpg to bypass the dangerous extensions blocklist.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
    evidence: The web server may then execute the file as PHP, resulting in remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-61457
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61457
rules:
  - title: Detects CVE-2026-61457 Exploitation - Grav API Plugin Double Extension Upload
    description: Detects exploitation of CVE-2026-61457 in Grav API plugin by identifying HTTP POST requests to media upload endpoints containing filenames with double extensions like '.php.jpg', bypassing validation.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1036.004
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A high-severity vulnerability, CVE-2026-61457, has been identified in the Grav API plugin (getgrav/grav-plugin-api) versions prior to 1.0.3. This flaw specifically impacts the API media controller's file upload validation mechanism. An authenticated attacker possessing `api.media.write` permissions can exploit this vulnerability by submitting a malicious file with a double extension, such as `shell.php.jpg`. The `HandlesMediaUploads::validateFileExtension()` function, which relies solely on `pathinfo($filename, PATHINFO_EXTENSION)`, will incorrectly identify `.jpg` as the primary extension, thereby circumventing the blocklist for dangerous file types. This bypass allows the attacker to upload and subsequently execute arbitrary PHP code on the underlying web server, leading to full remote code execution. This vulnerability poses a significant risk to the integrity and confidentiality of affected Grav installations.

## Attack Chain

1. An attacker gains authenticated access to a Grav instance, ideally with `api.media.write` permissions, either through compromised credentials or another initial access vector.
2. The attacker prepares a malicious PHP payload, such as a web shell (e.g., `shell.php`), designed to execute arbitrary commands.
3. To bypass file upload validation, the attacker renames the malicious PHP file with a double extension, for instance, `shell.php.jpg` or `malware.php.png`.
4. The attacker then initiates an HTTP POST request to the Grav API media controller endpoint, attempting to upload the specially crafted file (`shell.php.jpg`).
5. The vulnerable `HandlesMediaUploads::validateFileExtension()` function processes the file. Due to its reliance on `pathinfo($filename, PATHINFO_EXTENSION)`, it only inspects the final extension (`.jpg`), failing to detect the embedded `.php` extension.
6. The Grav API plugin allows the upload to proceed, storing the malicious `shell.php.jpg` file on the web server in an accessible directory.
7. The attacker directly accesses the uploaded file via a web browser or automated script, triggering its execution by the web server's PHP interpreter.
8. The malicious PHP code is executed on the server, granting the attacker remote code execution capabilities and potentially full control over the compromised system.

## Impact

Successful exploitation of CVE-2026-61457 can lead to complete compromise of the Grav web server. An attacker can achieve remote code execution, allowing them to install backdoors, deface websites, exfiltrate sensitive data, or establish persistence within the victim's network. While no specific victim counts or targeted sectors are available from the source, any organization using vulnerable versions of the Grav API plugin is at risk. The direct consequence is arbitrary command execution on the server, potentially leading to further network pivoting and broader system compromise.

## Recommendation

* Immediately patch CVE-2026-61457 by upgrading the Grav API plugin to version 1.0.3 or higher on all affected Grav installations.
* Deploy the Sigma rule titled "Detects CVE-2026-61457 Exploitation - Grav API Plugin Double Extension Upload" to your SIEM solution and monitor for suspicious HTTP POST requests.
* Ensure web server access logs are enabled and forwarded to your SIEM for analysis of `webserver` category events.
