---
title: Jupiter X Core WordPress Plugin Vulnerability Leads to Remote Code Execution
slug: 2024-01-jupiter-x-core-rce
description: The Jupiter X Core plugin for WordPress is vulnerable to remote code execution and stored cross-site scripting due to missing authorization and insufficient file type validation in versions up to 4.14.1, allowing authenticated attackers with subscriber-level access to upload malicious files.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - plugin
  - rce
  - xss
  - file-upload
vendors:
  - Jupiter
products:
  - Jupiter X Core
  - WordPress
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3533
rules:
  - title: Detect Suspicious File Uploading
    description: Detects attempts to upload suspicious file types (phar, svg, dfxp, xhtml) to a WordPress website.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect WordPress Plugin Update Activity
    description: Detects HTTP requests indicating WordPress plugin updates, which may indicate malicious activity or unexpected changes.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Jupiter X Core plugin for WordPress, a widely used theme customization tool, contains a critical vulnerability (CVE-2026-3533) affecting versions up to and including 4.14.1. This vulnerability stems from two key flaws: missing authorization checks on the `import_popup_templates()` function and inadequate file type validation within the `upload_files()` function. This allows authenticated attackers with minimal privileges (subscriber-level access and above) to upload arbitrary files to the WordPress server. The vulnerability was published on March 24, 2026. Successful exploitation can lead to Remote Code Execution (RCE) on servers configured to execute .phar files as PHP code (e.g., Apache with mod_php) or Stored Cross-Site Scripting (XSS) via .svg, .dfxp, or .xhtml files on any server configuration. This poses a significant risk to WordPress websites using the Jupiter X Core plugin, potentially allowing attackers to gain complete control of the server.

## Attack Chain

1.  An attacker gains subscriber-level access to a WordPress website using the vulnerable Jupiter X Core plugin (<= 4.14.1). This could be achieved through compromised credentials or by registering a new user account if registration is enabled.
2.  The attacker authenticates to the WordPress admin panel.
3.  The attacker leverages the missing authorization in `import_popup_templates()` to access file upload functionality that should be restricted to higher-level administrators.
4.  The attacker bypasses the insufficient file type validation in `upload_files()`, uploading a malicious .phar file disguised as a legitimate file type. Alternatively, they upload an .svg, .dfxp, or .xhtml file.
5.  If the server is configured to execute .phar files as PHP, the uploaded .phar file is executed, granting the attacker arbitrary code execution on the server.
6.  Alternatively, the uploaded .svg, .dfxp, or .xhtml file is stored on the server.
7.  When a user visits a page containing the uploaded file, the malicious script within the file is executed in their browser, leading to Stored Cross-Site Scripting (XSS).
8.  The attacker exploits the RCE to install malware, create backdoors, steal sensitive data, or deface the website. XSS can be used to steal admin credentials or redirect users to phishing sites.

## Impact

Successful exploitation of CVE-2026-3533 can have severe consequences. For servers vulnerable to RCE via .phar uploads, attackers can gain complete control, leading to data breaches, malware infections, and website defacement. The Stored XSS vulnerability allows attackers to inject malicious scripts into the website, potentially compromising user accounts and spreading malware. Given the widespread use of WordPress and the Jupiter X Core plugin, a large number of websites are potentially vulnerable. While specific victim numbers are unavailable, the impact could be substantial, affecting businesses, organizations, and individuals who rely on WordPress for their online presence.

## Recommendation

*   Immediately update the Jupiter X Core plugin to the latest version (greater than 4.14.1) to patch CVE-2026-3533.
*   If updating is not immediately feasible, disable the Jupiter X Core plugin temporarily as a mitigation measure.
*   Monitor web server logs for suspicious file uploads, specifically targeting .phar, .svg, .dfxp, and .xhtml file extensions. Use the provided Sigma rule `DetectSuspiciousFileUploading` to detect potential exploitation attempts.
*   Review WordPress user accounts and remove any unauthorized or suspicious accounts with subscriber-level access.
*   Configure your web server to properly handle file uploads to prevent execution of uploaded files. Ensure that .phar files are not executed as PHP scripts.
