---
title: D-Link DIR-822 A_101 Command Injection via DHCP Hostname
slug: 2026-04-dlink-dir822-cmd-injection
description: A command injection vulnerability exists in D-Link DIR-822 A_101, specifically within the udhcpd DHCP service; by manipulating the Hostname argument, a remote attacker can inject commands, but the affected product is no longer supported.
date: "2026-04-27T00:20:13Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - command-injection
  - dhcp
  - iot
vendors:
  - D-Link
products:
  - DIR-822 A_101
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-7067
    cvss: 7.3
    epss: 0.01028
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7067
  - https://tzh00203.notion.site/D-Link-DIR-822-A1-Command-Injection-in-udhcpd-via-DHCP-Hostname-337b5c52018a80d9b638d0fa59969e6b
  - https://vuldb.com/vuln/359642
rules:
  - title: DHCP Hostname Command Injection
    description: Detects command injection attempts in DHCP Hostname field
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - network_connection
      - zeek
  - title: DHCP Hostname Suspicious Characters
    description: Detects DHCP Hostname containing unusual characters that may indicate command injection attempts
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - network_connection
      - zeek
rules_count: 2
---

A command injection vulnerability, tracked as CVE-2026-7067, has been identified in D-Link DIR-822 hardware with firmware version A_101. The vulnerability lies within the udhcpd DHCP service, specifically in the handling of the Hostname argument in the /udhcpcd/dhcpd.c file. A remote attacker can exploit this flaw by injecting arbitrary commands through a crafted Hostname field in a DHCP request. While a proof-of-concept exploit is publicly available, this vulnerability is less impactful because the D-Link DIR-822 A_101 is no longer supported by the vendor, potentially limiting the number of affected devices.

## Attack Chain

1.  The attacker identifies a vulnerable D-Link DIR-822 A_101 device.
2.  The attacker crafts a malicious DHCP request containing a command injection payload in the Hostname field.
3.  The attacker sends the crafted DHCP request to the vulnerable device.
4.  The udhcpd service parses the DHCP request and extracts the Hostname.
5.  Due to insufficient input validation, the injected command within the Hostname is passed to the `system` function.
6.  The `system` function executes the injected command with the privileges of the udhcpd process (typically root).
7.  The attacker achieves arbitrary code execution on the device.
8.  The attacker can then perform actions such as gaining persistent access, modifying device configuration, or using the device as part of a botnet.

## Impact

Successful exploitation of this command injection vulnerability allows a remote, unauthenticated attacker to execute arbitrary code on the affected D-Link DIR-822 A_101 device. Given the end-of-life status of the product, patching is unlikely, leaving devices vulnerable. An attacker could leverage this vulnerability to gain complete control of the router, potentially compromising networks connected to it. The specific number of vulnerable devices is unknown, but the impact could be significant if many devices remain in use.

## Recommendation

*   Deploy the Sigma rule to detect command injection attempts via DHCP Hostname (Sigma rule: `DHCP Hostname Command Injection`).
*   Monitor network traffic for suspicious DHCP requests containing unusual characters or command sequences in the Hostname field, using network monitoring tools.
*   Consider network segmentation to isolate potentially vulnerable D-Link DIR-822 A_101 devices from critical network resources.
*   If replacement is not immediately feasible, implement strict access control lists on the firewall to limit access to the D-Link DIR-822 A_101 device's management interface.
