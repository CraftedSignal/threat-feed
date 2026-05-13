---
title: CVE-2026-0250 Palo Alto Networks GlobalProtect App Buffer Overflow Vulnerability
slug: 2026-05-globalprotect-buffer-overflow
description: CVE-2026-0250 is a medium severity buffer overflow vulnerability in Palo Alto Networks GlobalProtect App that could allow a man-in-the-middle attacker to disrupt system processes and potentially execute arbitrary code with SYSTEM privileges by intercepting and manipulating requests and responses between the Portal and Gateway.
date: "2026-05-13T16:04:16Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cve-2026-0250
  - buffer-overflow
  - man-in-the-middle
vendors:
  - Palo Alto Networks
products:
  - GlobalProtect App
  - GlobalProtect UWP App
affected_os:
  - Windows
  - Linux
  - macOS
  - Android
  - ChromeOS
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
references:
  - https://security.paloaltonetworks.com/CVE-2026-0250
rules:
  - title: Detect GlobalProtect App Process Creation
    description: Detects suspicious process creation by the GlobalProtect App which could be indicative of exploitation of CVE-2026-0250.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - windows
  - title: Detect Network Connection from GlobalProtect App
    description: Detects network connections from GlobalProtect App which may indicate exploitation of CVE-2026-0250
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

A buffer overflow vulnerability, identified as CVE-2026-0250, affects the Palo Alto Networks GlobalProtect App. This vulnerability can be exploited by a man-in-the-middle attacker positioned to intercept network traffic between a GlobalProtect Portal and Gateway. Successful exploitation could allow the attacker to disrupt system processes or potentially execute arbitrary code with SYSTEM privileges on the affected endpoint. The vulnerability stems from improper handling of requests and responses exchanged between the Portal and Gateway. The GlobalProtect app on iOS is not affected.

## Attack Chain

1.  The attacker positions themselves in a man-in-the-middle position on the network between the GlobalProtect client and the GlobalProtect Portal/Gateway.
2.  The GlobalProtect client initiates a connection to the GlobalProtect Portal or Gateway.
3.  The attacker intercepts the initial request from the GlobalProtect client.
4.  The attacker crafts a malicious response containing a buffer overflow payload.
5.  The attacker sends the malicious response to the GlobalProtect client.
6.  The GlobalProtect client processes the malicious response, triggering the buffer overflow.
7.  The buffer overflow allows the attacker to overwrite parts of memory, potentially corrupting system processes.
8.  If successful, the attacker gains the ability to execute arbitrary code with SYSTEM privileges, leading to full system compromise.

## Impact

Successful exploitation of CVE-2026-0250 can lead to disruption of system processes on the affected endpoint, potentially causing denial of service. In a more severe scenario, the attacker could achieve arbitrary code execution with SYSTEM privileges, leading to complete system compromise. While Palo Alto Networks is not aware of any malicious exploitation of this issue, the potential impact is significant, as it could allow an attacker to gain full control of the affected system.

## Recommendation

*   Upgrade GlobalProtect App on Windows to 6.3.3-h9 (6.3.3-999) or later, 6.2.8-h10 (6.2.8-948) or later, or 6.0.13 or later to patch CVE-2026-0250.
*   Upgrade GlobalProtect App on macOS to 6.3.3-h9 (6.3.3-999) or later, 6.2.8-h10 (6.2.8-948) or later, or 6.0.13 or later to patch CVE-2026-0250.
*   Upgrade GlobalProtect App on Linux to 6.3.3-h2 (6.3.3-42) or later, or 6.0.11 or later to patch CVE-2026-0250.
*   Upgrade GlobalProtect App on Android to 6.1.13 or later, or 6.0.14 or later to patch CVE-2026-0250.
*   Upgrade GlobalProtect App on ChromeOS to 6.1.13 or later, or 6.0.14 or later to patch CVE-2026-0250.
*   Upgrade GlobalProtect UWP App to 6.3.3-h10 or later to patch CVE-2026-0250.
