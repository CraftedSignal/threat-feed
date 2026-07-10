---
title: CVE-2026-6315 Use-After-Free Vulnerability in Google Chrome on Android
slug: 2024-01-02-chrome-use-after-free
description: A use-after-free vulnerability in Google Chrome on Android prior to version 147.0.7727.101 (CVE-2026-6315) allows remote attackers to execute arbitrary code by convincing a user to interact with a crafted HTML page through specific UI gestures.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - chrome
  - use-after-free
  - android
  - cve-2026-6315
  - remote-code-execution
vendors:
  - Google
products:
  - Chrome
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-6315
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6315
  - https://chromereleases.googleblog.com/2026/04/stable-channel-update-for-desktop_15.html
  - https://issues.chromium.org/issues/499247910
rules:
  - title: Detect Chrome Android Exploitation via UI Gestures
    description: Detects potential exploitation attempts of CVE-2026-6315 by monitoring for suspicious JavaScript events related to UI gestures.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - webserver
      - linux
  - title: Detect Chrome Android Exploit Page Access
    description: Detects access to potentially malicious HTML pages targeting Chrome on Android.
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

CVE-2026-6315 is a high-severity security vulnerability affecting Google Chrome on Android devices. Specifically, it is a use-after-free vulnerability within the Permissions component of the browser. The vulnerability exists in versions of Chrome for Android prior to 147.0.7727.101. A remote attacker can exploit this flaw by crafting a malicious HTML page and convincing a user to interact with it using specific UI gestures. Successful exploitation of this vulnerability allows the attacker to execute arbitrary code within the context of the Chrome browser on the targeted Android device, potentially leading to complete device compromise. The vulnerability was reported in April 2026.

## Attack Chain

1.  Attacker crafts a malicious HTML page designed to trigger the use-after-free condition in the Permissions component.
2.  The attacker hosts the crafted HTML page on a web server.
3.  The attacker convinces a user to visit the malicious page, likely through social engineering or other means.
4.  The user interacts with the page, performing specific UI gestures as manipulated by the attacker's code. This interaction is crucial to trigger the vulnerability.
5.  The crafted HTML page triggers the use-after-free vulnerability in the Permissions component of Chrome on Android.
6.  The attacker leverages the use-after-free vulnerability to corrupt memory within the Chrome process.
7.  The attacker injects and executes arbitrary code within the Chrome process's memory space, gaining control of the browser.
8.  The attacker leverages the compromised Chrome instance to perform malicious activities, such as stealing sensitive data, installing malware, or pivoting to other applications or the operating system.

## Impact

Successful exploitation of CVE-2026-6315 allows a remote attacker to execute arbitrary code on an affected Android device running Google Chrome. This can lead to complete compromise of the device, including data theft, malware installation, and unauthorized access to other applications and services. Given Chrome's widespread use on Android, this vulnerability poses a significant risk to a large number of users. The vulnerability is rated as high severity, emphasizing the potential for significant damage.

## Recommendation

*   Upgrade Google Chrome on Android to version 147.0.7727.101 or later to patch CVE-2026-6315.
*   Deploy the Sigma rule "Detect Chrome Android Exploitation via UI Gestures" to detect potential exploitation attempts based on suspicious javascript events within the browser.
*   Educate users about the risks of interacting with untrusted websites and performing unusual UI gestures.
*   Monitor web server logs for requests to suspicious-looking HTML pages that might be used to exploit this vulnerability.
