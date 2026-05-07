---
title: Linksys E1200 Authenticated Stack Buffer Overflow
slug: 2024-01-linksys-e1200-rce
description: A stack buffer overflow vulnerability in Linksys E1200 firmware version 2.0.04 and earlier allows an authenticated attacker to achieve remote code execution by sending a crafted HTTP POST request to the apply.cgi endpoint.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - buffer-overflow
  - rce
  - hardware
vendors:
  - Linksys
products:
  - E1200 Firmware (<= v2.0.04)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2025-60690
    cvss: 8.8
    epss: 0.05608
references:
  - https://www.exploit-db.com/exploits/52548
rules:
  - title: Detect Suspicious Linksys E1200 Apply.cgi Requests
    description: Detects POST requests to apply.cgi with unusually long lan_ipaddr parameters, indicative of a potential buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Reverse Shell via Telnet from Routers
    description: Detects telnet connections originating from router IP addresses, which may indicate a reverse shell spawned by an exploited device.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - firewall
rules_count: 2
---

The Linksys E1200 router, specifically firmware version 2.0.04 and earlier, is susceptible to an authenticated stack buffer overflow vulnerability (CVE-2025-60690). The vulnerability resides in the handling of the lan_ipaddr parameters within the apply.cgi endpoint. Exploitation requires the attacker to be authenticated and directly connected to the LAN. Successful exploitation allows an attacker to execute arbitrary code on the device, potentially leading to full system compromise. The exploit leverages a buffer overflow in the handling of the 'lan_ipaddr' parameters within the apply.cgi script. This vulnerability poses a significant risk to home and small business networks using the affected Linksys E1200 router.

## Attack Chain

1. The attacker gains access to the LAN network where the Linksys E1200 is connected.
2. The attacker authenticates to the Linksys E1200 web interface using valid credentials (e.g., admin:admin).
3. The attacker crafts an HTTP POST request targeting the `/apply.cgi` endpoint.
4. The POST request includes the `action=Apply` parameter and excessively long `lan_ipaddr_*` parameters designed to overflow a stack buffer.
5. The attacker injects shellcode into the overflowing buffer within the crafted `lan_ipaddr_3` parameter. The shellcode payload constructs a reverse shell.
6. The router's web server (`httpd`) processes the malicious POST request and attempts to write the oversized input into the stack buffer, triggering the overflow.
7. The injected shellcode is executed, establishing a reverse shell connection back to the attacker's machine.
8. The attacker gains remote code execution on the Linksys E1200 router, allowing for arbitrary command execution.

## Impact

Successful exploitation of this vulnerability allows an attacker to gain complete control of the affected Linksys E1200 router. This can lead to a variety of malicious activities, including eavesdropping on network traffic, modifying router configurations (DNS settings, firewall rules), and using the compromised router as a pivot point for further attacks within the local network. Given the widespread use of Linksys E1200 routers in homes and small businesses, this vulnerability has the potential to impact a large number of users.

## Recommendation

*   Apply available firmware updates from Linksys to patch CVE-2025-60690 when they become available.
*   Monitor web server logs for suspicious POST requests to `/apply.cgi` with abnormally long `lan_ipaddr_*` parameters using the Sigma rule provided.
*   Implement network segmentation to limit the impact of a compromised router on other network devices.
*   Enforce strong and unique passwords for all router accounts to prevent unauthorized access.
