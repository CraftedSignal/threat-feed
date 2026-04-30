---
title: Foreman WebSocket Proxy Command Injection Vulnerability (CVE-2026-1961)
slug: 2026-03-foreman-rce
description: A command injection vulnerability exists in Foreman's WebSocket proxy, enabling remote code execution on the Foreman server via a malicious compute resource server when a user accesses VM VNC console functionality.
date: "2026-03-26T13:16:27Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - command-injection
  - rce
  - foreman
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-1961
rules:
  - title: Foreman Suspicious Process Execution via Command Injection
    description: Detects suspicious process execution originating from the Foreman process, indicative of command injection exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - linux
  - title: Foreman Websocket Proxy Handling Malicious Hostnames
    description: Detects suspicious websocket connections originating from the Foreman process where the hostname contains shell metacharacters
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

CVE-2026-1961 identifies a critical command injection vulnerability within the Foreman application, specifically affecting the WebSocket proxy implementation. This flaw stems from the use of unsanitized hostname values obtained from compute resource providers during the construction of shell commands. An attacker who controls a malicious compute resource server can exploit this vulnerability to execute arbitrary code on the Foreman server. This is achieved when a user interacts with the VM VNC…
