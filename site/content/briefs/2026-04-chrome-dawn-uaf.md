---
title: Google Chrome Dawn Use-After-Free Vulnerability (CVE-2026-6310)
slug: 2026-04-chrome-dawn-uaf
description: A use-after-free vulnerability (CVE-2026-6310) in Google Chrome's Dawn component allows a remote attacker, having compromised the renderer process, to potentially execute a sandbox escape via a specially crafted HTML page.
date: "2026-04-16T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-6310
  - use-after-free
  - sandbox escape
  - google chrome
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-6310
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6310
  - https://chromereleases.googleblog.com/2026/04/stable-channel-update-for-desktop_15.html
  - https://issues.chromium.org/issues/497969820
rules:
  - title: Detect Chrome Renderer Process Spawning Unusual Processes
    description: Detects unusual processes spawned by the Chrome renderer process, which may indicate a sandbox escape attempt following exploitation of CVE-2026-6310.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Chrome Renderer Process Network Connection to Non-Standard Ports
    description: Detects network connections initiated from the Chrome renderer process to non-standard ports, potentially indicating command and control activity after exploiting CVE-2026-6310.
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

CVE-2026-6310 is a high-severity vulnerability affecting Google Chrome versions prior to 147.0.7727.101. The vulnerability lies within the Dawn component, a library used for interacting with the WebGPU API. An attacker who has already compromised the Chrome renderer process can exploit this use-after-free vulnerability to potentially escape the Chrome sandbox. Successful exploitation requires the attacker to craft a malicious HTML page that triggers the vulnerability in Dawn, enabling them to execute arbitrary code outside the confines of the renderer process and potentially gain control of the user's system. This poses a significant risk to users browsing untrusted websites.

## Attack Chain

1.  The attacker crafts a malicious HTML page specifically designed to trigger the use-after-free vulnerability in the Dawn component of Google Chrome.
2.  The victim visits the malicious HTML page via a compromised website, a phishing link, or other social engineering techniques.
3.  The HTML page leverages the WebGPU API to interact with the Dawn component.
4.  The malicious code manipulates memory in a way that leads to a use-after-free condition within Dawn.
5.  The attacker exploits the use-after-free vulnerability to overwrite memory and gain control of program execution.
6.  The attacker leverages the compromised renderer process to attempt a sandbox escape.
7.  If successful, the attacker can execute arbitrary code outside the Chrome sandbox.
8.  The attacker can then install malware, steal sensitive data, or perform other malicious actions on the victim's system.

## Impact

Successful exploitation of CVE-2026-6310 allows an attacker to escape the Chrome sandbox, a security mechanism designed to isolate web content from the rest of the system. This could lead to arbitrary code execution on the victim's machine, potentially allowing the attacker to install malware, steal sensitive information, or perform other malicious activities. Given Chrome's widespread use, a successful exploit could impact a large number of users across various sectors.

## Recommendation

*   Upgrade Google Chrome to version 147.0.7727.101 or later to patch CVE-2026-6310.
*   Implement a network detection rule to identify potentially malicious HTML pages that exploit WebGPU and trigger the use-after-free condition.
*   Monitor process creation events for unusual processes spawned by chrome.exe after the renderer process is compromised, as this may indicate a sandbox escape.
