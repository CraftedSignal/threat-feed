---
title: WWBN AVideo Unauthenticated Remote Code Execution via YPTSocket Plugin (CVE-2026-40911)
slug: 2024-01-wwbn-avideo-rce
description: WWBN AVideo version 29.0 and prior is vulnerable to unauthenticated arbitrary Javascript execution via the YPTSocket plugin, allowing an attacker to execute arbitrary code in the context of connected users, leading to account takeover and data theft.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - avideo
  - rce
  - websocket
  - cve-2026-40911
vendors:
  - WWBN
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1185
    technique_name: Drive-by Compromise
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-40911
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40911
rules:
  - title: Detect Suspicious WebSocket Traffic to AVideo YPTSocket Plugin
    description: Detects suspicious WebSocket traffic to the AVideo YPTSocket plugin, potentially indicating exploitation attempts of CVE-2026-40911.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - webserver
      - linux
  - title: Detect eval() Usage in YPTSocket Script
    description: Detects requests serving the YPTSocket script potentially used for code execution.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - webserver
      - linux
rules_count: 2
---

WWBN AVideo, an open-source video platform, is susceptible to a critical vulnerability (CVE-2026-40911) affecting versions 29.0 and prior. The flaw resides in the YPTSocket plugin's WebSocket server, which unsafely relays attacker-supplied JSON messages to all connected clients without proper sanitization of the `msg` and `callback` fields. This lack of input validation allows an unauthenticated attacker to inject arbitrary JavaScript code that executes within the context of any connected user's browser session. Since tokens are minted for anonymous users and are not revalidated, this vulnerability can be exploited to achieve universal account takeover, session theft, and execution of privileged actions within the AVideo platform. The vulnerability is addressed in commit c08694bf6264eb4decceb78c711baee2609b4efd. Successful exploitation allows attackers to compromise all active user sessions, including those of administrators.

## Attack Chain

1. An unauthenticated attacker connects to the AVideo platform's WebSocket server via the YPTSocket plugin.
2. The attacker crafts a malicious JSON message containing JavaScript code within the `msg` and/or `callback` fields.
3. The attacker sends the crafted JSON message to the WebSocket server.
4. The YPTSocket plugin's server relays the attacker-supplied JSON message to all connected clients without sanitization.
5. On the client side, the `plugin/YPTSocket/script.js` file receives the JSON message.
6. The `eval()` function at line 568 (`json.msg.autoEvalCodeOnHTML`) and/or line 95 (`json.callback`) in `plugin/YPTSocket/script.js` executes the attacker-injected JavaScript code.
7. The injected JavaScript code can perform actions such as stealing session cookies, creating new administrative accounts, or modifying data within the AVideo platform.
8. The attacker gains control of user accounts and performs privileged actions on the compromised AVideo platform.

## Impact

Successful exploitation of CVE-2026-40911 allows an unauthenticated attacker to execute arbitrary JavaScript code within the context of any connected user's session on a vulnerable AVideo platform. This can lead to complete account takeover, including administrator accounts, resulting in unauthorized access to sensitive data, modification of system settings, and potential data breaches. The vulnerability has a CVSS v3.1 base score of 10.0, indicating its critical severity. The number of victims and specific sectors targeted are unknown but could potentially affect any organization using a vulnerable version of AVideo.

## Recommendation

*   Upgrade WWBN AVideo to a version containing the fix from commit c08694bf6264eb4decceb78c711baee2609b4efd to remediate CVE-2026-40911.
*   Deploy the Sigma rules provided in this brief to your SIEM to detect potential exploitation attempts targeting the YPTSocket plugin.
*   Monitor web server logs for suspicious POST requests to WebSocket endpoints associated with the YPTSocket plugin, as these could indicate exploitation attempts (see example rule referencing category "webserver").
