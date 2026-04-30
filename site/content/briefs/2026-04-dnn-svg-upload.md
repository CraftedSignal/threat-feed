---
title: DNN (DotNetNuke) SVG Upload Vulnerability (CVE-2026-40321)
slug: 2026-04-dnn-svg-upload
description: DNN (formerly DotNetNuke) before 10.2.2 is vulnerable to stored cross-site scripting (XSS) via malicious SVG file uploads, potentially leading to account takeover and arbitrary code execution.
date: "2026-04-18T12:00:00Z"
type: advisory
types:
  - advisory
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

DNN (formerly DotNetNuke) is an open-source web content management system (CMS) built on the .NET framework. Prior to version 10.2.2, a stored cross-site scripting (XSS) vulnerability exists due to insufficient sanitization of SVG files. Attackers can exploit CVE-2026-40321 by uploading a crafted SVG file containing malicious JavaScript. This script can then be executed in the context of other users, including administrators, upon accessing the uploaded SVG. Successful exploitation could lead to session hijacking, account takeover, and potentially arbitrary code execution on the server. Version 10.2.2 addresses this vulnerability by implementing proper sanitization of SVG uploads. The vulnerability affects both authenticated and unauthenticated users, increasing the attack surface.

## Attack Chain

1. An attacker identifies a DNN instance running a version prior to 10.2.2.
2. The attacker crafts a malicious SVG file containing embedded JavaScript code designed to perform actions such as stealing cookies or redirecting users.
3. The attacker uploads the malicious SVG file to the DNN instance, potentially through a media library or profile picture upload feature.
4. A user (either authenticated or unauthenticated) views the page or element where the malicious SVG is displayed.
5. The user's browser executes the embedded JavaScript code within the SVG file.
6. The malicious script steals the user's session cookie or redirects them to a phishing page.
7. If the compromised user has administrative privileges, the attacker uses the stolen cookie to access the DNN administration panel.
8. The attacker leverages their administrative access to inject malicious code into the DNN website or install a backdoor for persistent access.

## Impact

Successful exploitation of this vulnerability (CVE-2026-40321) can lead to a range of negative consequences. Attackers can hijack user sessions, potentially gaining unauthorized access to sensitive data and administrative functions. An attacker can deface the website, inject malware, or steal sensitive information. Because DNN is often used in enterprise environments, this could lead to significant data breaches and reputational damage. The number of affected installations is potentially high, given the widespread use of DNN.

## Recommendation

*   Upgrade DNN installations to version 10.2.2 or later to patch CVE-2026-40321, as recommended by the vendor.
*   Implement the "Detect Suspicious SVG Uploads" Sigma rule to identify attempts to upload SVG files containing potentially malicious script content.
*   Monitor web server logs for HTTP requests with the ".svg" extension and inspect the request body for suspicious JavaScript patterns to proactively detect malicious SVG uploads using the "Web Server Suspicious SVG Upload" Sigma rule.
*   Implement strict input validation and sanitization measures for all file uploads, especially SVG files, to prevent the injection of malicious code.
