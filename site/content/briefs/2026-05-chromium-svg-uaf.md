---
title: Chromium CVE-2026-7906 Use-After-Free in SVG
slug: 2026-05-chromium-svg-uaf
description: CVE-2026-7906 is a use-after-free vulnerability in the SVG component of Chromium, also affecting Microsoft Edge.
date: "2026-05-07T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*
tags:
  - chromium
  - use-after-free
  - svg
  - cve-2026-7906
vendors:
  - Google
  - Microsoft
products:
  - Chrome
  - Edge
cves:
  - id: CVE-2026-7906
    cvss: 8.8
    epss: 0.00074
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-7906
  - https://chromereleases.googleblog.com/2026
rules:
  - title: Detect CVE-2026-7906 Exploitation via SVG Download
    description: Detects CVE-2026-7906 exploitation — suspicious SVG files downloaded from the internet
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - file_event
      - windows
  - title: Detect CVE-2026-7906 Exploitation via Javascript
    description: Detects CVE-2026-7906 exploitation — detects javascript attempting to manipulate svg objects
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-7906 is a use-after-free vulnerability present within the Scalable Vector Graphics (SVG) component of the Chromium browser engine. Since Microsoft Edge is built upon Chromium, it is also affected by this flaw. A remote attacker could potentially exploit this vulnerability to execute arbitrary code by crafting a malicious SVG document. Successful exploitation requires a user to open the malicious SVG file in a vulnerable browser, opening the door to potential phishing campaigns or drive-by download attacks. Defenders should prioritize patching their Chromium-based browsers to the latest versions.

## Attack Chain

1.  Attacker crafts a malicious SVG file containing a use-after-free trigger.
2.  Attacker hosts the malicious SVG file on a website or distributes it via email.
3.  Victim visits the website or opens the email, triggering the browser to load the SVG file.
4.  The browser attempts to render the SVG file.
5.  The use-after-free vulnerability is triggered during SVG rendering, leading to memory corruption.
6.  Attacker leverages the memory corruption to gain control of the browser process.
7.  Attacker injects shellcode into the browser process.
8.  The injected shellcode executes, allowing the attacker to perform arbitrary actions on the victim's system.

## Impact

Successful exploitation of this use-after-free vulnerability could lead to arbitrary code execution within the context of the user running the affected browser. This allows the attacker to potentially install malware, steal sensitive information, or perform other malicious actions. Given the widespread use of Chromium-based browsers like Chrome and Edge, this vulnerability poses a significant threat to a large number of users.

## Recommendation

*   Apply the latest security updates for Google Chrome and Microsoft Edge to patch CVE-2026-7906.
*   Deploy the Sigma rule `Detect CVE-2026-7906 Exploitation via SVG Download` to detect malicious SVG files being downloaded by users.
*   Deploy the Sigma rule `Detect CVE-2026-7906 Exploitation via Javascript` to detect javascript attempting to exploit the vulnerability.
