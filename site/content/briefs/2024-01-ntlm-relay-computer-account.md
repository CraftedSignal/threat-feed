---
title: Potential NTLM Relay Attack against a Computer Account
slug: 2024-01-ntlm-relay-computer-account
description: This rule detects potential NTLM relay attacks against computer accounts by identifying coercion attempts followed by authentication events originating from a different host, indicating that an attacker has captured and relayed the server's computer account hash to execute code on behalf of the compromised system.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - ntlm-relay
  - windows
vendors:
  - Microsoft
products:
  - Windows Security Event Logs
affected_os:
  - windows
references:
  - https://github.com/p0dalirius/windows-coerced-authentication-methods
  - https://www.thehacker.recipes/a-d/movement/mitm-and-coerced-authentications
  - https://www.synacktiv.com/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025
  - https://github.com/Orange-Cyberdefense/ocd-mindmaps/blob/main/excalimap/mindmap/ad/authenticated.md
rules:
  - title: Potential NTLM Relay - File Share Access Attempt
    description: Detects file share access attempts to named pipes commonly abused in NTLM relay attacks.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1187
    data_sources:
      - file_event
      - windows
  - title: Potential NTLM Relay - Computer Account Authentication from Different Host
    description: Detects authentication events using a computer account (ending in $) from a different host than the account's origin, indicative of NTLM relay.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1187
    data_sources:
      - authentication
      - windows
rules_count: 2
---

This detection rule identifies potential NTLM relay attacks targeting computer accounts in Windows environments. The attack involves coercing a target server to authenticate to an attacker-controlled system and then relaying that authentication to another service. It focuses on detecting a sequence of events: initial coercion attempts against specific named pipes known to be vulnerable, followed by authentication attempts using the target server's computer account from a different host. This activity can allow an attacker to gain unauthorized access and execute commands with the privileges of the compromised computer account. The rule leverages Windows Security Event Logs to identify these patterns, providing a mechanism for defenders to detect and respond to NTLM relay attacks. The detection is based on research from 2025/2026 on coerced authentication methods and NTLM reflection techniques.

## Attack Chain

1.  The attacker gains initial access to a machine within the network.
2.  The attacker initiates a coercion attack against a target server, forcing it to authenticate to a malicious endpoint. This often involves leveraging vulnerabilities in services such as Spoolss, Netlogon, or other RPC services. The attacker uses methods outlined in the referenced coercion authentication research.
3.  The target server attempts to access a named pipe on the attacker-controlled system. This is logged as a File Share event (Event ID 5145) on the target server, indicating access to a named pipe like `Spoolss`, `netdfs`, `lsarpc`, `lsass`, `netlogon`, `samr`, `efsrpc`, `FssagentRpc`, `eventlog`, `winreg`, `srvsvc`, `dnsserver`, or `WinsPipe`.
4.  The attacker captures the NTLM authentication attempt from the target server.
5.  The attacker relays the captured NTLM authentication to another service on the network, impersonating the target server. The authentication event is logged (Event ID 4624 or 4625), showing a logon attempt using the NTLM protocol and a computer account (username ending in "$").
6.  The authentication attempt originates from a different IP address than the target server's IP, indicating the relay.
7.  If successful, the attacker gains unauthorized access to the service and can execute commands or access data with the privileges of the target server's computer account.
8.  The attacker leverages the compromised computer account to move laterally within the network, potentially gaining access to sensitive resources or escalating privileges further.

## Impact

A successful NTLM relay attack can allow attackers to gain control of critical systems and data. By compromising a computer account, attackers can move laterally within the network, access sensitive information, and potentially disrupt business operations. The number of victims and the extent of the damage can vary depending on the scope of the attacker's activities after compromising the computer account. Organizations in any sector that rely on Windows networks and Active Directory are vulnerable. Failure to detect and prevent these attacks can lead to significant financial losses, reputational damage, and regulatory penalties.

## Recommendation

*   Enable and monitor Windows Security Event Logs, specifically for Event IDs 5145 (File Share access), 4624 (Successful Logon), and 4625 (Failed Logon), as these are crucial for detecting NTLM relay attempts.
*   Deploy the Sigma rules provided in this brief to your SIEM to detect potential NTLM relay attacks based on the sequence of file access and authentication events.
*   Investigate any alerts generated by the Sigma rules, focusing on the source and target of the authentication events, the named pipes accessed, and any follow-on activity.
*   Review and harden NTLM configuration to mitigate relay attacks, and consider disabling NTLM where possible in favor of more secure authentication protocols like Kerberos.
*   Enable SMB signing and Extended Protection for Authentication to prevent NTLM relay attacks.
*   Implement network segmentation and access controls to limit the scope of potential NTLM relay attacks.
*   Apply the "Setup" configurations by enabling the recommended Windows audit policies to ensure the events required by the rules are generated.
