---
title: Remote Command Injection in D-Link DSL-3782
slug: 2026-09-dlink-command-injection
description: An unauthenticated remote command injection vulnerability in the D-Link DSL-3782 router allows attackers to execute arbitrary system commands via the Diagnostics component.
date: "2026-09-15T05:38:59Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:h:dlink:dsl-3782:2016-07-28:*:*:*:*:*:*:*
tags:
  - cve-2026-90880
  - command-injection
  - network-security
vendors:
  - D-Link
products:
  - DSL-3782 (2016-07-28)
cves:
  - id: CVE-2026-90880
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90880
---

A command injection vulnerability (CVE-2026-90880) has been identified in the D-Link DSL-3782 router, specifically within the 2016-07-28 firmware version. The flaw resides in the Diagnostics component, triggered by improper input validation within the system function handling the /cgi-bin/New_GUI/Set/Diagnostics.asp script. An unauthenticated remote attacker can inject malicious shell commands by manipulating the Addr argument. Publicly available exploit code exists, increasing the risk of exploitation for remote system compromise or unauthorized access to the network device. Defenders should prioritize isolating vulnerable legacy hardware, as these devices are often targeted for inclusion in botnets or used as entry points into internal networks.

## Attack Chain

1. Attacker performs network reconnaissance to identify reachable D-Link DSL-3782 management interfaces.
2. Attacker crafts a malicious HTTP GET or POST request targeting the /cgi-bin/New_GUI/Set/Diagnostics.asp endpoint.
3. Attacker injects shell metacharacters or command strings into the 'Addr' parameter (e.g., ; id or | /bin/sh).
4. The router's web server processes the request and passes the tainted 'Addr' value to a system-level function without proper sanitization.
5. The underlying operating system executes the attacker-supplied command with root or administrative privileges.
6. The attacker establishes a reverse shell or downloads a malicious payload to gain persistent access to the device.
7. Final objective: The device is recruited into a botnet or used as a pivot point for lateral movement into the local network.

## Impact

Successful exploitation allows for full system control over the affected D-Link DSL-3782 router. This can lead to unauthorized network monitoring, traffic interception, internal network reconnaissance, and the deployment of malware. As this device is a consumer-grade router, impact includes potential data exfiltration and complete loss of confidentiality and integrity for all traffic traversing the device.

## Recommendation

* Monitor network traffic for anomalous HTTP requests directed at /cgi-bin/New_GUI/Set/Diagnostics.asp containing shell metacharacters.
* Disconnect affected D-Link DSL-3782 devices from the public internet immediately.
* If a firmware update is unavailable, ensure the web management interface is not accessible from the WAN side.
* Implement egress filtering on the gateway to detect and block non-standard outbound connections originating from network infrastructure components.
