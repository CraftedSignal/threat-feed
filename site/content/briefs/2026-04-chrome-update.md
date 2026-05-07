---
title: Google Chrome Security Update Released
slug: 2026-04-chrome-update
description: Google released a security advisory to address vulnerabilities in Chrome for Desktop versions prior to 147.0.7727.137/138 on Windows/Mac and 147.0.7727.137 on Linux, prompting users to apply necessary updates.
date: "2026-04-29T11:43:30Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - browser
  - vulnerability
  - chrome
  - update
vendors:
  - Google
products:
  - Chrome
affected_os:
  - Windows
  - macOS
  - Linux
references:
  - https://cyber.gc.ca/en/alerts-advisories/google-chrome-security-advisory-av26-402
  - https://chromereleases.googleblog.com/2026/04/stable-channel-update-for-desktop_28.html
rules:
  - title: Detect Chrome Renderer Code Injection
    description: Detects potential code injection attempts within Chrome renderer processes by monitoring for suspicious process creation events.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1055
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Chrome Outbound Connection
    description: Detects suspicious outbound network connections from Chrome processes, potentially indicating C2 communication.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

On April 28, 2026, Google addressed vulnerabilities in Chrome for Desktop versions prior to 147.0.7727.137/138 on Windows/Mac and 147.0.7727.137 on Linux. While the specific nature of these vulnerabilities remains undisclosed in the advisory, the urgency of the update suggests potential risks ranging from arbitrary code execution to information disclosure. Timely patching is crucial for maintaining the security posture of systems using the Chrome browser. This update affects a broad user base, highlighting the importance of prompt action by both individual users and system administrators.

## Attack Chain

Due to the lack of specific vulnerability details, the following is a generalized attack chain based on common browser vulnerabilities:

1.  Attacker identifies a vulnerable Chrome version (prior to 147.0.7727.137/138 on Windows/Mac and 147.0.7727.137 on Linux).
2.  Attacker crafts a malicious web page containing JavaScript code designed to exploit the vulnerability.
3.  The victim visits the malicious web page, either through a direct link or a compromised advertisement.
4.  The JavaScript code executes within the context of the victim's Chrome browser.
5.  The exploit successfully triggers the vulnerability, potentially leading to memory corruption or other unintended behavior.
6.  The attacker leverages the initial exploit to inject and execute shellcode within the browser process.
7.  The shellcode establishes a connection to a command-and-control (C2) server, allowing the attacker to remotely control the compromised browser.
8.  The attacker uses the compromised browser to perform further actions, such as stealing cookies, injecting keyloggers, or pivoting to other systems on the network.

## Impact

Failure to apply the Chrome security update may lead to arbitrary code execution, information disclosure, or other malicious activities on affected systems. A successful exploit could allow attackers to gain control of the user's browser, steal sensitive data, or use the compromised system as a foothold for further attacks within the network. The impact is widespread, affecting all users of Chrome on Desktop who have not updated to the latest version.

## Recommendation

*   Apply the necessary updates to Chrome for Desktop to version 147.0.7727.137/138 (Windows/Mac) and 147.0.7727.137 (Linux) as recommended in the [Google Chrome Security Advisory](https://chromereleases.googleblog.com/2026/04/stable-channel-update-for-desktop_28.html).
*   Deploy the Sigma rule `Detect Chrome Renderer Code Injection` to identify potential code injection attempts within Chrome renderer processes.
*   Monitor network connections from Chrome processes using the `Detect Suspicious Chrome Outbound Connection` Sigma rule to identify potential C2 communications.
