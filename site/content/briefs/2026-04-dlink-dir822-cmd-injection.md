---
title: D-Link DIR-822 A_101 Command Injection via DHCP Hostname
slug: 2026-04-dlink-dir822-cmd-injection
description: A command injection vulnerability exists in D-Link DIR-822 A_101, specifically within the udhcpd DHCP service; by manipulating the Hostname argument, a remote attacker can inject commands, but the affected product is no longer supported.
date: "2026-04-27T00:20:13Z"
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

A command injection vulnerability, tracked as CVE-2026-7067, has been identified in D-Link DIR-822 hardware with firmware version A_101. The vulnerability lies within the udhcpd DHCP service, specifically in the handling of the Hostname argument in the /udhcpcd/dhcpd.c file. A remote attacker can exploit this flaw by injecting arbitrary commands through a crafted Hostname field in a DHCP request. While a proof-of-concept exploit is publicly available, this vulnerability is less impactful…
