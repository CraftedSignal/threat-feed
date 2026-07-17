---
title: Flask-Reuploaded Extension Denylist Bypass via Case-Folding Asymmetry
slug: 2026-07-flask-reuploaded-case-folding-bypass
description: An incomplete fix for CVE-2026-27641 in Flask-Reuploaded versions up to and including 1.5.0 allows attackers to bypass extension denylists through case-folding asymmetry, enabling the upload of malicious files with dangerous extensions (e.g., shell.PHP) that can lead to remote code execution on case-insensitive execution environments.
date: "2026-07-17T20:12:56Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:jugmac00:flask-reuploaded:*:*:*:*:*:python:*:*
tags:
  - web-vulnerability
  - file-upload
  - rce
  - python
  - flask
  - incomplete-fix
products:
  - Flask-Reuploaded <= 1.5.0
affected_os:
  - Windows
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker controlling `name` stores a file with a denied extension by varying case (`shell.PHP`, `evil.pHp`).
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: The bypassed config is the one the library's own docs recommend for blocking scripts...An app that followed this guidance to block scripts is exactly what this variant defeats.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: On case-insensitive execution surfaces → remote code execution under the web server's privileges
    confidence_band: high
cves:
  - id: CVE-2026-27641
    cvss: 9.8
    epss: 0.01046
references:
  - https://github.com/advisories/GHSA-937x-gpqr-72gg
---

A critical vulnerability exists in the Flask-Reuploaded library, affecting all versions up to and including 1.5.0, stemming from an incomplete fix for CVE-2026-27641. This flaw allows attackers to bypass documented extension denylist mechanisms, specifically when a `name` override is provided to the `UploadSet.save()` function. The core issue lies in a case-folding asymmetry: the re-validation logic for the `name` override uses a case-preserving extension extractor, whereas the security policy's denied tokens are typically lowercase. This discrepancy enables attackers to upload files with mixed-case dangerous extensions, such as `shell.PHP` or `evil.pHp`, which would normally be blocked. If the application is deployed on a system with case-insensitive file resolution and execution, such as Windows or macOS filesystems, or specific web server configurations (e.g., Apache with `AddHandler`/`AddType`), successful exploitation leads to remote code execution under the web server's privileges, re-enabling the impact that the original CVE-2026-27641 aimed to prevent.

## Attack Chain

1. An attacker identifies a web application utilizing Flask-Reuploaded and configured with an `UploadSet` that employs a denylist to prevent specific file types (e.g., scripts).
2. The attacker crafts a malicious file, such as a PHP web shell, specifically designed for remote code execution, (e.g., `shell.PHP`).
3. The attacker sends an authenticated HTTP request to the application's file upload endpoint, which uses the vulnerable `UploadSet.save()` function.
4. Within this request, the attacker supplies a `name` override parameter for the uploaded file, specifying the malicious filename with mixed casing (e.g., `name="shell.PHP"` or `name="evil.pHp"`).
5. Due to the incomplete fix for CVE-2026-27641, the `UploadSet.save()` function's re-validation logic fails to normalize the mixed-case extension to lowercase, thus bypassing the configured denylist.
6. The application saves the malicious file (e.g., `shell.PHP`) to the configured upload directory on the web server's filesystem.
7. The attacker then makes a subsequent HTTP request to directly access the uploaded malicious file (e.g., `http://example.com/uploads/shell.PHP?c=id`).
8. On a server environment where file extensions are resolved or executed case-insensitively (e.g., Windows/macOS filesystems or specific Apache `AddHandler`/`AddType` configurations), the web server executes the PHP web shell, granting the attacker remote code execution.

## Impact

The successful exploitation of this vulnerability bypasses Flask-Reuploaded's documented extension denylist mechanism for scripts and executables. This allows an attacker to upload and store files with dangerous, mixed-case extensions (e.g., `.PHP`, `.pHp`) within the application's served upload directory. The primary impact is remote code execution (RCE) under the web server's privileges if the affected application is hosted on a case-insensitive execution surface such as Windows or macOS filesystems, or if the web server (e.g., Apache) is configured to handle extensions case-insensitively. This outcome effectively re-enables the critical code execution risk that the original CVE-2026-27641 aimed to mitigate, potentially compromising the integrity, confidentiality, and availability of the affected web application and underlying server. Any web application using Flask-Reuploaded with a denylist configuration is susceptible.

## Recommendation

* Update Flask-Reuploaded to a version that addresses the case-folding asymmetry in `UploadSet.save()`. The patch should normalize the extension before the policy check using `ext = extension(basename).lower()` or `extension(lowercase_ext(basename))`.
* Alternatively, modify your Flask-Reuploaded configuration to make `extension_allowed` or the policy containers case-insensitive to ensure consistent evaluation of extensions.
* Audit your application's file upload logic to ensure that user-supplied filenames are rigorously validated and processed using case-normalized extensions consistently across all security checks.
* Deploy the `attack.t1190` rules in your SIEM to detect attempts to exploit public-facing applications through suspicious file uploads.
* Ensure your log sources, particularly `webserver` logs, capture full HTTP request details, including method, URI stem, and query parameters, to aid in investigating `attack.t1190` activity.
