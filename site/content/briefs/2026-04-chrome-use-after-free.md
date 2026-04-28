---
title: Google Chrome Prerender Use-After-Free Vulnerability (CVE-2026-6299)
slug: 2026-04-chrome-use-after-free
description: A use-after-free vulnerability (CVE-2026-6299) in Google Chrome's Prerender component before version 147.0.7727.101 allows a remote attacker to execute arbitrary code by crafting a malicious HTML page.
date: "2026-04-16T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - CVE-2026-6299
  - use-after-free
  - google-chrome
  - code-execution
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-6299
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6299
  - https://chromereleases.googleblog.com/2026/04/stable-channel-update-for-desktop_15.html
  - https://issues.chromium.org/issues/497053588
rules:
  - title: Detect Chrome Use-After-Free Exploit Attempt
    description: Detects attempts to exploit use-after-free vulnerabilities in Chrome by monitoring for suspicious patterns in web server logs.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.007
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Chrome Suspicious Process Spawning
    description: Detects suspicious process spawning from Chrome browser, indicating potential exploitation.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1059.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-6299 is a critical security vulnerability affecting Google Chrome versions prior to 147.0.7727.101. This use-after-free vulnerability resides within the Prerender component, which is responsible for preloading web pages to improve browsing speed. A remote attacker can exploit this vulnerability by crafting a malicious HTML page and enticing a user to open it in a vulnerable version of Chrome. Successful exploitation leads to arbitrary code execution within the context of the user running Chrome. This poses a significant risk to users as attackers could potentially gain control of their systems, steal sensitive information, or install malware. The Chromium security team has classified this vulnerability as "Critical," highlighting the severity and potential impact of this flaw. This vulnerability was patched in version 147.0.7727.101.

## Attack Chain

1.  The attacker crafts a malicious HTML page that leverages the use-after-free vulnerability in the Prerender component.
2.  The attacker hosts the malicious HTML page on a web server.
3.  The attacker entices the victim to visit the malicious website via social engineering or other methods.
4.  The victim's browser (Chrome version < 147.0.7727.101) parses the HTML page and attempts to pre-render the page.
5.  The use-after-free vulnerability is triggered in the Prerender component during the rendering process.
6.  The attacker gains control of the memory location previously occupied by the freed object.
7.  The attacker executes arbitrary code within the context of the Chrome browser process.
8.  The attacker can now perform actions such as installing malware, stealing sensitive data, or further compromising the system.

## Impact

Successful exploitation of CVE-2026-6299 allows a remote attacker to execute arbitrary code on the victim's machine. This can lead to complete system compromise, including data theft, malware installation, and unauthorized access. Given Chrome's widespread usage, a successful exploit could potentially impact a large number of users across various sectors. The severity of this vulnerability is further amplified by its "Critical" classification by the Chromium security team.

## Recommendation

*   Immediately update Google Chrome to version 147.0.7727.101 or later to patch CVE-2026-6299.
*   Consider deploying the Sigma rule `Detect Chrome Use-After-Free Exploit Attempt` to identify potential exploitation attempts in your environment.
*   Monitor web server logs for suspicious requests to identify potential attackers attempting to exploit CVE-2026-6299.
