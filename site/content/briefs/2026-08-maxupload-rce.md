---
title: Arbitrary File Upload in MaxUpload WordPress Plugin
slug: 2026-08-maxupload-rce
description: The MaxUpload WordPress plugin is vulnerable to unauthenticated remote code execution via insufficient filename validation during chunk assembly.
date: "2026-08-15T06:16:33Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - WordPress
products:
  - MaxUpload – Big File Uploads – Increase Maximum File Upload Size (<= 1.4.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This is due to a filename-validation mismatch in the handle_upload function where extension and MIME checks are applied to the uploaded chunk's filename but not to the final assembled filename.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This makes it possible for unauthenticated attackers to upload files that may be executable, which makes remote code execution possible.
    confidence_band: high
cves:
  - id: CVE-2026-15965
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15965
rules:
  - title: Detects CVE-2026-15965 Exploitation - Unauthenticated Arbitrary File Upload
    description: Detects potential exploitation attempts of CVE-2026-15965 by identifying suspicious POST requests to the handle_upload function where the resumableFilename parameter contains executable extensions.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

The MaxUpload - Big File Uploads - Increase Maximum File Upload Size plugin for WordPress (versions 1.4.0 and earlier) contains a critical arbitrary file upload vulnerability. The vulnerability resides in the handle_upload function, which manages file chunk uploads. The plugin fails to validate the final filename generated from the 'resumableFilename' parameter during the file assembly process, despite correctly applying validation checks to individual uploaded chunks. This mismatch allows unauthenticated attackers to supply a malicious filename that bypasses extension and MIME type restrictions. By successfully manipulating the assembly process, an attacker can upload executable files (such as .php files) to the web server, leading to unauthenticated remote code execution. This poses a significant risk to WordPress installations where this plugin is active, as it facilitates direct compromise of the underlying web server infrastructure.

## Impact

Successful exploitation allows an unauthenticated remote attacker to execute arbitrary code on the affected WordPress server. This could lead to full site takeover, data exfiltration, lateral movement within the network, or the installation of persistent backdoors. Given the nature of the vulnerability, the potential impact is critical for any organization hosting enterprise or sensitive data on a WordPress platform using this plugin.

## Recommendation

* Update the "MaxUpload - Big File Uploads - Increase Maximum File Upload Size" plugin to the latest patched version immediately.
* If patching is not possible, disable the plugin and remove the affected code path from the server until a fix is deployed.
* Monitor web server access logs for anomalous POST requests targeting the handle_upload endpoint, particularly those containing suspicious filename patterns or non-standard file extensions in the resumableFilename parameter.
* Deploy file integrity monitoring on the WordPress 'wp-content/uploads' directory to detect the unauthorized creation of executable files.
