---
title: Microsoft SharePoint Server RCE Vulnerability
slug: 2026-05-sharepoint-rce
description: An authenticated remote attacker can exploit a vulnerability in Microsoft SharePoint Server 2016, Microsoft SharePoint Server 2019, and Microsoft SharePoint to execute arbitrary code.
date: "2026-05-26T12:20:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sharepoint
  - rce
  - code_execution
vendors:
  - Microsoft
products:
  - SharePoint Server 2016
  - SharePoint Server 2019
  - SharePoint
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1652
rules:
  - title: Detect Suspicious SharePoint POST Requests
    description: Detects suspicious POST requests to SharePoint servers that may indicate an exploitation attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect SharePoint Web Shell Creation
    description: Detects the creation of web shells in SharePoint directories.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Microsoft SharePoint Server 2016, 2019, and SharePoint are vulnerable to a remote code execution (RCE) attack. An authenticated attacker can exploit this vulnerability to execute arbitrary code within the context of the SharePoint application. The vulnerability impacts organizations utilizing these versions of SharePoint server and could lead to data compromise, system takeover, and further malicious activities within the network. Successful exploitation allows the attacker to gain control over the SharePoint server, potentially impacting sensitive data and business operations. Defenders need to implement detection and patching strategies to mitigate this risk.

## Attack Chain

1. The attacker authenticates to the SharePoint server using compromised or valid credentials.
2. The attacker crafts a malicious request targeting a vulnerable endpoint within SharePoint.
3. This request exploits a flaw that allows for arbitrary code execution, such as deserialization or improper input validation.
4. The server processes the malicious request, triggering the vulnerability.
5. The attacker injects and executes arbitrary code on the SharePoint server.
6. This code could install a web shell for persistent access.
7. The attacker leverages the web shell or other remote access to move laterally within the network.
8. The attacker compromises sensitive data or other critical systems.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code on the SharePoint server. This could lead to the complete compromise of the server, including access to sensitive data stored within SharePoint, modification of SharePoint content, and the potential for lateral movement to other systems on the network. The number of affected organizations is potentially large, given the widespread use of SharePoint.

## Recommendation

*   Monitor SharePoint servers for suspicious activity, including unusual requests and unauthorized access attempts.
*   Examine web server logs for POST requests with unusual parameters or content.
*   Implement the Sigma rules provided to detect potential exploitation attempts.
*   Apply patches released by Microsoft as soon as they are available to remediate the vulnerability.
