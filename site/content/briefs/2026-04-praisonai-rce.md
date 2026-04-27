---
title: PraisonAI Unauthenticated Remote Session Hijacking Vulnerability (CVE-2026-40289)
slug: 2026-04-praisonai-rce
description: PraisonAI versions before 4.5.139 and praisonaiagents versions before 1.5.140 are vulnerable to unauthenticated remote session hijacking due to missing authentication and a bypassable origin check on the /ws WebSocket endpoint, enabling unauthorized remote control and data leakage.
date: "2026-04-14T04:18:47Z"
severities:
  - critical
tags:
  - cve-2026-40289
  - websocket
  - remote-code-execution
  - praisonai
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1213
    technique_name: Data from Information Repositories
cves:
  - id: CVE-2026-40289
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40289
rules:
  - title: Detect WebSocket Connection Without Origin Header
    description: Detects WebSocket connections to the /ws endpoint without an Origin header, potentially indicating an attempt to exploit CVE-2026-40289.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - network
    techniques:
      - T1189
    data_sources:
      - network_connection
      - linux
  - title: Detect Suspicious PraisonAI start_session Message
    description: Detects a 'start_session' message sent to the PraisonAI /ws endpoint, potentially indicating session hijacking (CVE-2026-40289).
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

PraisonAI, a multi-agent team system, is affected by a critical vulnerability (CVE-2026-40289) in versions prior to 4.5.139 and praisonaiagents versions prior to 1.5.140. The vulnerability lies in the browser bridge component ("praisonai browser start"), which lacks proper authentication and has a bypassable origin check on its /ws WebSocket endpoint. The server, binding to 0.0.0.0 by default, inadequately validates the Origin header, permitting connections from non-browser clients omitting…
