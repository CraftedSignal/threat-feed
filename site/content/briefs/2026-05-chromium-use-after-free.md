---
title: Chromium Use-After-Free Vulnerability in ANGLE (CVE-2026-7359)
slug: 2026-05-chromium-use-after-free
description: A use-after-free vulnerability in the ANGLE graphics engine within Chromium (CVE-2026-7359) allows for potential exploitation in Google Chrome and Microsoft Edge.
date: "2026-05-01T02:21:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - use-after-free
  - chromium
  - edge
  - chrome
  - cve-2026-7359
vendors:
  - Google
  - Microsoft
products:
  - Chrome
  - Edge
cves:
  - id: CVE-2026-7359
    cvss: 8.8
    epss: 0.00011
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-7359
  - https://chromereleases.googleblog.com/2025
rules:
  - title: Detect Suspicious WebGL Usage
    description: Detects potential exploitation attempts leveraging WebGL, which utilizes ANGLE, by monitoring for unusual or malicious parameters in the URI query.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect High Volume of 400/500 Errors After Patching
    description: Detects a potential increase in 400/500 HTTP errors that may indicate ongoing exploitation attempts after applying the patch for CVE-2026-7359.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1489
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-7359 describes a use-after-free vulnerability present in ANGLE (Almost Native Graphics Layer Engine), a crucial component of the Chromium open-source project. This vulnerability impacts applications that utilize the Chromium engine, most notably Google Chrome and Microsoft Edge. While the provided source does not give specific exploitation details, use-after-free vulnerabilities can allow for arbitrary code execution. Google Chrome has already addressed this vulnerability, and Microsoft Edge has incorporated the fix from Chromium. This vulnerability matters to defenders because successful exploitation could lead to compromise of the browser and potentially the underlying system.

## Attack Chain

1.  An attacker crafts a malicious web page containing JavaScript code that leverages a flaw in ANGLE's memory management.
2.  A user visits the malicious web page through Chrome or Edge.
3.  The JavaScript code triggers the use-after-free vulnerability by freeing a memory object in ANGLE and then attempting to access it again.
4.  This memory corruption leads to a controlled crash or allows the attacker to overwrite memory with arbitrary data.
5.  The attacker leverages the memory overwrite to inject malicious code into the browser process.
6.  The injected code executes within the context of the browser, granting the attacker access to user data, cookies, and other sensitive information.
7.  The attacker may then use this access to perform actions on behalf of the user, such as stealing credentials, installing malware, or spreading the attack to other systems.
8.  The attacker achieves arbitrary code execution on the user's system, potentially leading to full system compromise.

## Impact

A successful exploit of CVE-2026-7359 could allow an attacker to execute arbitrary code within the context of the affected browser (Chrome or Edge). This can lead to sensitive information disclosure, data theft, and potentially full system compromise. The scope of impact is broad, affecting any user who visits a malicious webpage while using a vulnerable version of Chrome or Edge. Since Chrome and Edge are widely used, this vulnerability poses a significant risk.

## Recommendation

*   Deploy the Sigma rule `Detect Suspicious WebGL Usage` to identify potential exploitation attempts targeting ANGLE via WebGL.
*   Monitor web server logs for suspicious requests (cs-uri-query) that may be related to the exploitation of CVE-2026-7359.
*   Ensure that all Chrome and Edge installations are updated to the latest versions to patch CVE-2026-7359.
