---
title: PraisonAI Unauthenticated Remote Session Hijacking Vulnerability (CVE-2026-40289)
slug: 2026-04-praisonai-rce
description: PraisonAI versions before 4.5.139 and praisonaiagents versions before 1.5.140 are vulnerable to unauthenticated remote session hijacking due to missing authentication and a bypassable origin check on the /ws WebSocket endpoint, enabling unauthorized remote control and data leakage.
date: "2026-04-14T04:18:47Z"
type: advisory
types:
  - advisory
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

PraisonAI, a multi-agent team system, is affected by a critical vulnerability (CVE-2026-40289) in versions prior to 4.5.139 and praisonaiagents versions prior to 1.5.140. The vulnerability lies in the browser bridge component ("praisonai browser start"), which lacks proper authentication and has a bypassable origin check on its /ws WebSocket endpoint. The server, binding to 0.0.0.0 by default, inadequately validates the Origin header, permitting connections from non-browser clients omitting this header. This flaw allows an unauthenticated attacker to remotely hijack sessions and broadcast automation actions and outputs. This can lead to unauthorized remote control of connected browser automation sessions, leakage of sensitive page context and automation results, and misuse of model-backed browser actions. Defenders must prioritize patching affected systems to mitigate this severe risk.

## Attack Chain

1.  Attacker identifies a vulnerable PraisonAI instance with network access to the browser bridge component.
2.  Attacker establishes a direct WebSocket connection to the /ws endpoint of the browser bridge, omitting the Origin header to bypass the weak origin check.
3.  Attacker sends a "start_session" message to the WebSocket endpoint.
4.  The server routes the attacker's "start_session" request to the first idle browser-extension WebSocket, effectively hijacking that session.
5.  The hijacked browser session begins executing commands dictated by the attacker.
6.  All automation actions and outputs resulting from the hijacked session are broadcast back to the attacker via the WebSocket connection.
7.  Attacker gains unauthorized remote control of the connected browser automation session.
8.  Attacker exfiltrates sensitive data and/or misuses model-backed browser actions.

## Impact

Successful exploitation of CVE-2026-40289 can lead to complete compromise of PraisonAI browser automation sessions. An attacker can gain unauthorized remote control, potentially leading to leakage of sensitive page context and automation results. Furthermore, they can misuse model-backed browser actions. The vulnerability affects all environments where the bridge is network-reachable. The severity of the impact is high, as it allows for unauthenticated remote code execution within the context of the PraisonAI browser extension.

## Recommendation

*   Upgrade PraisonAI to version 4.5.139 or later, and praisonaiagents to version 1.5.140 or later to patch CVE-2026-40289.
*   Monitor network connections to the /ws endpoint on PraisonAI servers (logsource category: network_connection, product: windows/linux).
*   Deploy the Sigma rule to detect suspicious websocket connections without origin header (see rule below).
*   Implement network segmentation to limit network access to the PraisonAI browser bridge component.
