---
title: Grav Form Plugin Anonymous Page Content Overwrite Vulnerability
slug: 2024-01-09-grav-form-plugin-overwrite
description: Grav Form plugin versions before 9.1.0 allow unauthenticated users to overwrite page content by uploading a malicious markdown file, leading to potential privilege escalation by crafting a new super-admin user.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - grav
  - cms
  - file-upload
  - privilege-escalation
  - content-overwrite
vendors:
  - getgrav
products:
  - grav-plugin-form
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1134
    technique_name: Access Token Manipulation
references:
  - https://github.com/advisories/GHSA-w4rc-p66m-x6qq
rules:
  - title: Detect Grav Form Plugin Page Content Overwrite Attempt
    description: Detects attempts to upload markdown or YAML files via the Grav Form plugin, potentially overwriting existing page content.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1505
    data_sources:
      - webserver
      - linux
  - title: Detect Grav Admin User Creation via Form Submission
    description: Detects attempts to create new admin users by abusing the Grav Form plugin vulnerability.
    platform: sigma
    severity: critical
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1134
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Grav CMS Form plugin, specifically in versions prior to 9.1.0, contains a vulnerability allowing unauthenticated users to overwrite existing page content. This flaw resides in the file upload handling mechanism within `user/plugins/form/classes/Form.php`, where the filename of an uploaded file can be controlled via a POST request. The `Utils::checkFilename()` function insufficiently filters filenames, failing to block `.md` extensions. By exploiting this, an attacker can upload a malicious `.md` file, crafted to overwrite the content of an existing page. This enables attackers to inject arbitrary content, including YAML frontmatter, leading to privilege escalation by creating new administrator accounts. This vulnerability was tested on Form version 9.0.3, released on April 28th.

## Attack Chain

1.  An unauthenticated attacker identifies a Grav page using the Form plugin with a file upload field that accepts all file types (`accept: ['*']`).
2.  The attacker crafts a malicious `.md` file containing YAML frontmatter designed to create a new administrator account (e.g., `viaup.yaml` as described in the PoC).
3.  The attacker uploads the malicious `.md` file, setting the `filename` parameter in the POST request to match the target page's content file name (e.g., `form.md`).
4.  The `Form::uploadFiles()` function processes the upload, using the attacker-controlled filename to store the file in flash storage.
5.  Upon form submission, `Form::copyFiles()` moves the uploaded file to its final destination, overwriting the original `.md` file of the target page.
6.  The attacker accesses the target page via a `GET` request, causing Grav to parse the newly overwritten `.md` file and its injected YAML frontmatter.
7.  The injected YAML frontmatter creates a new super-admin user.
8.  The attacker uses the credentials of the newly created super-admin user to log in and gain administrative control of the Grav CMS instance.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to overwrite existing page content, inject malicious code, and ultimately escalate their privileges to super-admin. This grants them complete control over the Grav CMS instance, potentially leading to data theft, website defacement, or further malicious activities. This vulnerability impacts any Grav page allowing file uploads with insufficiently restricted file types and can result in complete compromise of the Grav CMS.

## Recommendation

*   Apply the remediation patch described in the advisory by upgrading to Grav Form plugin version 9.1.0 or later to address CVE-2026-42845.
*   Implement the provided code snippet within `user/plugins/form/classes/Form.php` to block uploads of sensitive page content file types (`.md`, `.yaml`, `.yml`, `.json`, `.twig`) to prevent page content overwrites.
*   Add `md, yaml, yml, json, twig, ini` to the `security.uploads_dangerous_extensions` list in Grav's configuration to prevent these file types from being processed.
*   Deploy the Sigma rule "Detect Grav Form Plugin Page Content Overwrite Attempt" to identify potential exploitation attempts by monitoring for uploads of markdown or YAML files to the pages directory.
*   Monitor web server logs for POST requests to form submission endpoints that contain the `filename` parameter with values matching page content filenames (e.g., `form.md`, `default.md`).
