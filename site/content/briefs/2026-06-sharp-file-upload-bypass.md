---
title: Sharp Laravel Admin Panel Unrestricted File Upload Vulnerability
slug: 2026-06-sharp-file-upload-bypass
description: The code16/sharp Laravel admin panel package contains a vulnerability in its file upload endpoint that allows authenticated users to bypass all file type restrictions by manipulating the validation_rule parameter, potentially leading to Remote Code Execution (RCE) if the storage disk is configured to be publicly accessible.
date: "2026-03-25T20:03:11Z"
severities:
  - high
tags:
  - laravel
  - file-upload
  - rce
  - code16/sharp
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://github.com/advisories/GHSA-fr76-5637-w3g9
  - https://github.com/code16/sharp
  - https://laravel.com/docs/13.x/filesystem
  - https://github.com/code16/sharp/pull/714
ioc_counts:
  url: 5
rules:
  - title: Detect Sharp File Upload Bypass Attempt
    description: Detects attempts to bypass file upload restrictions in Sharp Laravel admin panel by manipulating the validation_rule parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious PHP Upload via Sharp
    description: Detects the upload of PHP files to a webserver via the Sharp file upload endpoint.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The `code16/sharp` Laravel admin panel package, specifically versions before 9.20.0, is vulnerable to unrestricted file upload. An authenticated user can manipulate the `validation_rule` parameter in the `/api/form/upload` endpoint to bypass file type restrictions. This vulnerability stems from insufficient server-side validation of the client-supplied `validation_rule`, which is directly passed to the Laravel validator. Successfully exploiting this vulnerability allows an attacker to upload…
