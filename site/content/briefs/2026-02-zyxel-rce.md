---
title: Critical Command Injection Vulnerability in Zyxel Routers (CVE-2026-13942)
slug: 2026-02-zyxel-rce
description: A critical command injection vulnerability (CVE-2026-13942) in the UPnP function of Zyxel routers allows remote attackers to execute arbitrary operating system commands by sending crafted UPnP SOAP requests.
date: "2026-02-27T12:00:00Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - zyxel
  - router
  - command injection
  - cve-2026-13942
  - upnp
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://ccb.belgium.be/advisories/warning-critical-vulnerability-various-zyxel-routers-patch-immediately
  - https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-null-pointer-dereference-and-command-injection-vulnerabilities-in-certain-4g-lte-5g-nr-cpe-dsl-ethernet-cpe-fiber-onts-security-routers-and-wireless-extenders-02-24-2026
  - https://nvd.nist.gov/vuln/detail/CVE-2025-13942
rules:
  - title: Detect Suspicious UPnP SOAP Requests
    description: Detects suspicious UPnP SOAP requests that may indicate a command injection attempt, focusing on common command injection patterns.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - network_connection
      - zeek
  - title: Detect Outbound Network Connection from Zyxel Routers
    description: Detects outbound network connections initiated from Zyxel routers, which may indicate compromise
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

A critical command injection vulnerability, tracked as CVE-2026-13942, has been discovered in the UPnP (Universal Plug and Play) service of Zyxel routers. The vulnerability stems from insufficient validation of input within the UPnP SOAP request processing.  An unauthenticated, remote attacker can exploit this flaw by sending specially crafted UPnP SOAP requests to the affected device. This allows the attacker to inject and execute arbitrary operating system commands with elevated privileges on…
