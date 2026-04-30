---
title: Google Chrome Proxy Use-After-Free Vulnerability (CVE-2026-6297)
slug: 2026-04-chrome-use-after-free
description: CVE-2026-6297 is a critical use-after-free vulnerability in the Proxy component of Google Chrome before version 147.0.7727.101, enabling a privileged network attacker to potentially achieve sandbox escape via a crafted HTML page.
date: "2026-04-15T20:16:38Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - use-after-free
  - chrome
  - sandbox escape
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-6297
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6297
  - https://chromereleases.googleblog.com/2026/04/stable-channel-update-for-desktop_15.html
  - https://issues.chromium.org/issues/493628982
rules:
  - title: Detect Chrome Sandbox Escape via Crafted HTML
    description: Detects potential sandbox escape attempts in Google Chrome by monitoring for specific HTML elements or attributes often used in exploit code.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1027
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Chrome Process Memory Access
    description: Detects potential sandbox escape attempts in Google Chrome by monitoring for process accessing Chrome's process memory
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1027
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-6297 is a critical security flaw affecting Google Chrome users. The vulnerability, a use-after-free issue within the Proxy component, exists in versions prior to 147.0.7727.101. Successfully exploiting this vulnerability would allow an attacker positioned in a privileged network location to potentially break out of Chrome's sandbox. The attack vector involves a specially crafted HTML page delivered to the victim. This is a critical vulnerability because a successful exploit could lead to arbitrary code execution within the context of the user running Chrome, potentially leading to data theft, system compromise, or further lateral movement within a network.

## Attack Chain

1.  Attacker gains a privileged network position, such as through ARP poisoning or DNS spoofing.
2.  The victim user browses to a website or is redirected to a website controlled by the attacker.
3.  The attacker injects a malicious HTML page into the victim's browser session.
4.  The malicious HTML page leverages JavaScript to trigger the use-after-free vulnerability in Chrome's Proxy component.
5.  The use-after-free condition allows the attacker to corrupt memory within the Chrome process.
6.  By carefully crafting the memory corruption, the attacker gains control of program execution.
7.  The attacker executes arbitrary code within the Chrome sandbox.
8.  The attacker leverages the initial code execution within the sandbox to attempt a sandbox escape and gain access to the underlying operating system.

## Impact

Successful exploitation of CVE-2026-6297 allows an attacker in a privileged network position to perform a sandbox escape. This can lead to arbitrary code execution on the user's machine, potentially compromising sensitive data, allowing for further exploitation of the system, and enabling lateral movement within the network. Due to the widespread use of Chrome, this vulnerability has the potential to affect a large number of users across various sectors.

## Recommendation

*   Upgrade Google Chrome to version 147.0.7727.101 or later to patch CVE-2026-6297.
*   Deploy the Sigma rule "Detect Chrome Sandbox Escape via Crafted HTML" to identify potential exploitation attempts within your environment.
*   Monitor network traffic for signs of ARP poisoning or DNS spoofing, which are common prerequisites for exploiting vulnerabilities like CVE-2026-6297.
