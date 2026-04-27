---
title: DNN (DotNetNuke) SVG Upload Vulnerability (CVE-2026-40321)
slug: 2026-04-dnn-svg-upload
description: DNN (formerly DotNetNuke) before 10.2.2 is vulnerable to stored cross-site scripting (XSS) via malicious SVG file uploads, potentially leading to account takeover and arbitrary code execution.
date: "2026-04-18T12:00:00Z"
severities:
  - high
tags:
  - dnn
  - dotnetnuke
  - svg
  - xss
  - cve-2026-40321
  - upload
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Information Discovery
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1185
    technique_name: Drive-by Password Stealing
cves:
  - id: CVE-2026-40321
    cvss: 8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40321
  - https://github.com/dnnsoftware/Dnn.Platform/releases/tag/v10.2.2
  - https://github.com/dnnsoftware/Dnn.Platform/security/advisories/GHSA-ffq7-898w-9jc4
rules:
  - title: Detect Suspicious SVG Uploads
    description: Detects the upload of SVG files containing potential malicious script content.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - file_event
      - windows
  - title: Web Server Suspicious SVG Upload
    description: Detects suspicious SVG uploads via web server logs, identifying requests with SVG extensions and script-like content.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - windows
rules_count: 2
---

DNN (formerly DotNetNuke) is an open-source web content management system (CMS) built on the .NET framework. Prior to version 10.2.2, a stored cross-site scripting (XSS) vulnerability exists due to insufficient sanitization of SVG files. Attackers can exploit CVE-2026-40321 by uploading a crafted SVG file containing malicious JavaScript. This script can then be executed in the context of other users, including administrators, upon accessing the uploaded SVG. Successful exploitation could lead…
