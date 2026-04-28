---
title: Google Chrome GPU Out-of-Bounds Write Vulnerability (CVE-2026-6314)
slug: 2026-04-chrome-gpu-oob-write
description: Google Chrome versions prior to 147.0.7727.101 are vulnerable to an out-of-bounds write in the GPU process (CVE-2026-6314), allowing a remote attacker with GPU process compromise to potentially perform a sandbox escape via a crafted HTML page.
date: "2026-04-16T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - chrome
  - gpu
  - oob-write
  - sandbox-escape
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-6314
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6314
  - https://chromereleases.googleblog.com/2026/04/stable-channel-update-for-desktop_15.html
  - https://issues.chromium.org/issues/498782145
rules:
  - title: Detect Chrome GPU Process Crash
    description: Detects crashes in the Chrome GPU process, which could be indicative of exploitation attempts against vulnerabilities like CVE-2026-6314.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious HTML Redirection
    description: Detects redirections from normal websites to potential phishing sites or exploit delivery locations
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-6314 is a security vulnerability affecting Google Chrome versions prior to 147.0.7727.101. The vulnerability resides within the GPU process and is classified as an out-of-bounds write. Successful exploitation could allow a remote attacker who has already compromised the GPU process to perform a sandbox escape, potentially gaining broader system access. The vulnerability can be triggered by a crafted HTML page. The Chromium security team has rated this vulnerability as High severity. This vulnerability was patched in the 147.0.7727.101 release.

## Attack Chain

1.  The attacker crafts a malicious HTML page designed to trigger the out-of-bounds write in the GPU process.
2.  The victim visits the malicious HTML page using a vulnerable version of Google Chrome.
3.  The HTML page leverages JavaScript to initiate a GPU-related operation that triggers the vulnerable code path.
4.  The GPU process attempts to write data outside of the intended memory buffer due to a flaw in the code.
5.  This out-of-bounds write corrupts memory within the GPU process.
6.  The attacker leverages the memory corruption to overwrite critical data structures or code within the GPU process.
7.  By manipulating the GPU process's memory, the attacker attempts to escape the Chrome sandbox.
8.  If successful, the attacker gains the ability to execute arbitrary code outside the sandbox, potentially compromising the user's system.

## Impact

Successful exploitation of CVE-2026-6314 allows an attacker to escape the Chrome sandbox. This allows the attacker to potentially execute arbitrary code on the victim's machine. While the exact number of victims is unknown, all users of Google Chrome versions prior to 147.0.7727.101 are potentially vulnerable. A successful sandbox escape could lead to data theft, malware installation, or other malicious activities, depending on the privileges of the compromised user.

## Recommendation

*   Upgrade Google Chrome to version 147.0.7727.101 or later to patch CVE-2026-6314.
*   Deploy the Sigma rule `Detect Chrome GPU Process Crash` to identify potential exploitation attempts based on abnormal process termination.
*   Monitor web server logs for requests to suspicious HTML pages (cs-uri-query, cs-uri-stem) that could be used to deliver the exploit.
