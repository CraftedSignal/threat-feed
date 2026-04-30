---
title: D-Link DIR-825/825R OS Command Injection Vulnerability (CVE-2026-4627)
slug: 2026-03-dlink-command-injection
description: CVE-2026-4627 is an OS command injection vulnerability in the handler_update_system_time function of the libdeuteron_modules.so file in the NTP Service component of D-Link DIR-825 and DIR-825R devices, which can be exploited remotely by authenticated attackers.
date: "2026-03-24T05:16:24Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - command-injection
  - router
  - legacy-device
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4627
  - https://vuldb.com/?id.352495
rules:
  - title: Detect Outbound Network Connection from libdeuteron_modules.so
    description: Detects outbound network connections from the libdeuteron_modules.so library, which may indicate exploitation of CVE-2026-4627
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - network_connection
      - linux
  - title: Detect Suspicious Process Creation from NTP Service
    description: Detects suspicious process creation events originating from the NTP service which may indicate command injection.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-4627 is an OS command injection vulnerability affecting D-Link DIR-825 and DIR-825R routers, specifically versions 1.0.5 and 4.5.1. The vulnerability resides within the `handler_update_system_time` function of the `libdeuteron_modules.so` file, which is part of the NTP service. An attacker with administrative privileges can inject arbitrary OS commands by manipulating the input to this function. The vulnerability can be exploited remotely, allowing a threat actor to potentially gain…
