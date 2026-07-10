---
title: Laravel Mediable Arbitrary File Upload Vulnerability (CVE-2026-4809)
slug: 2024-01-laravel-mediable-rce
description: plank/laravel-mediable through version 6.4.0 is vulnerable to arbitrary file upload via client-supplied MIME types, potentially leading to remote code execution if the uploaded file is stored in a web-accessible location.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - laravel-mediable
  - file-upload
  - rce
  - CVE-2026-4809
vendors:
  - plank
products:
  - laravel-mediable
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4809
rules:
  - title: Detect Suspicious PHP File Upload with Image MIME Type
    description: Detects attempts to upload PHP files with image MIME types, which could indicate exploitation of CVE-2026-4809 in Laravel Mediable.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-4809
      - execution
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect PHP Code in Uploaded Files
    description: Detects PHP code within uploaded files based on file content.
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-4809
      - execution
      - initial_access
    techniques:
      - T1189
    data_sources:
      - file_event
      - linux
rules_count: 2
---

plank/laravel-mediable, a package for Laravel applications, is vulnerable to arbitrary file upload. Specifically, versions through 6.4.0 are susceptible to CVE-2026-4809, which allows a remote attacker to upload malicious files by manipulating the MIME type during the upload process. This occurs when the application trusts client-supplied MIME types. An attacker can upload a file containing PHP code disguised as an image file. Due to the lack of proper server-side validation, this can bypass upload restrictions. The vulnerability was reported in March 2026, and at the time of the NVD publication, no patch was available, and the vendor had not responded to disclosure attempts. This poses a significant risk to applications using the vulnerable package, potentially leading to remote code execution and complete system compromise.

## Attack Chain

1. The attacker identifies a Laravel application using a vulnerable version (<= 6.4.0) of the plank/laravel-mediable package.
2. The attacker locates a file upload function within the application that utilizes the mediable package.
3. The attacker crafts a malicious PHP file containing code intended for remote code execution.
4. The attacker sets the MIME type of the malicious file to a benign image type (e.g., image/jpeg, image/png) in the HTTP request headers.
5. The attacker uploads the crafted file to the vulnerable endpoint.
6. The application, trusting the client-supplied MIME type, stores the file without proper validation.
7. The attacker determines the storage location of the uploaded file (e.g., through directory traversal or other means).
8. The attacker accesses the uploaded PHP file via a web browser, triggering the execution of the malicious code, leading to remote code execution on the server.

## Impact

A successful exploit of CVE-2026-4809 can lead to arbitrary file upload and remote code execution. This allows an attacker to gain complete control of the affected web server, potentially leading to data breaches, defacement of the website, or further attacks on internal systems. While specific victim counts are unavailable, any application using the vulnerable plank/laravel-mediable package is at risk. The vulnerability poses a critical threat to organizations relying on the affected applications, as it can result in significant financial and reputational damage.

## Recommendation

*   Monitor web server logs for suspicious file uploads with image MIME types but PHP file extensions. Deploy the "Detect Suspicious PHP File Upload with Image MIME Type" Sigma rule to identify such attempts based on webserver logs.
*   Implement server-side MIME type validation to ensure uploaded files match their declared MIME type.
*   Restrict file uploads to non-executable directories. Configure web servers to prevent execution of PHP code in upload directories.
*   Upgrade to a patched version of plank/laravel-mediable as soon as one becomes available. Check the vendor's website or the package repository for updates.
