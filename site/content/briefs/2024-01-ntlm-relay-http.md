---
title: Potential Local NTLM Relay via HTTP
slug: 2024-01-ntlm-relay-http
description: Adversaries may coerce local NTLM authentication over HTTP via WebDAV named-pipe paths (Print Spooler, SRVSVC), then relay credentials to elevate privileges.
date: "2024-01-09T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ntlm-relay
  - credential-access
  - windows
  - webdav
vendors:
  - Elastic
  - Microsoft
  - SentinelOne
  - Crowdstrike
products:
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: Man-in-the-Middle
references:
  - https://github.com/med0x2e/NTLMRelay2Self
  - https://github.com/topotam/PetitPotam
  - https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py
rules:
  - title: Potential Local NTLM Relay via HTTP
    description: Detects rundll32.exe executing davclnt.dll,DavSetCookie targeting HTTP pipe paths indicative of NTLM relay attempts.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1557.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious DavClient Usage
    description: Detects the loading of davclnt.dll by uncommon processes, potentially indicating WebDAV abuse.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1557.001
    data_sources:
      - image_load
      - windows
rules_count: 2
---

This detection identifies attempts to coerce local NTLM authentication over HTTP through WebDAV named-pipe paths, focusing on Print Spooler and SRVSVC. Attackers can exploit this vulnerability, often combined with tools like NTLMRelay2Self, PetitPotam, or modified versions of krbrelayx's printerbug.py, to relay the obtained credentials and escalate their privileges within the network. This technique allows attackers to bypass traditional security measures by leveraging legitimate Windows protocols for malicious purposes. Successful exploitation can lead to domain dominance and unauthorized access to sensitive resources. This activity is often associated with post-exploitation activity following initial access via other means.

## Attack Chain

1.  An attacker gains initial access to a Windows system.
2.  The attacker executes `rundll32.exe` to load `davclnt.dll` using the `DavSetCookie` function.
3.  The `rundll32.exe` process is invoked with arguments specifying a named pipe path over HTTP, such as `http*/print/pipe/*`, `http*/pipe/spoolss`, or `http*/pipe/srvsvc`.
4.  The system attempts to authenticate to the specified HTTP endpoint using NTLM.
5.  The attacker intercepts the NTLM authentication request.
6.  Using a relay tool like NTLMRelay2Self or ntlmrelayx, the attacker relays the captured NTLM credentials to another service or machine.
7.  The attacker leverages the relayed credentials to escalate privileges or gain unauthorized access to network resources.
8.  The attacker may then perform lateral movement, data exfiltration, or other malicious activities.

## Impact

Successful exploitation allows attackers to escalate privileges within the compromised system and potentially the entire domain. This can lead to unauthorized access to sensitive data, deployment of ransomware, or other destructive activities. The impact ranges from data breaches and financial losses to complete system compromise. Depending on the targeted accounts, the attacker may be able to achieve domain administrator privileges.

## Recommendation

*   Deploy the Sigma rule "Potential Local NTLM Relay via HTTP" to your SIEM to detect the execution of `rundll32.exe` with specific arguments indicative of NTLM relay attempts.
*   Enable Sysmon process creation logging to ensure the necessary data is available for the Sigma rule to function correctly.
*   Monitor network connections originating from processes that load `davclnt.dll` to identify potential NTLM relay traffic.
*   Investigate and block the usage of tools like NTLMRelay2Self, PetitPotam, and ntlmrelayx within the environment.
*   Implement mitigations for NTLM relay attacks, such as enabling Extended Protection for Authentication (EPA) and disabling NTLM where possible.
*   Review and restrict the usage of WebClient service and Print Spooler service where not required.
