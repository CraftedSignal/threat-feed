---
title: Potential Kerberos Relay Attack via Coerced Authentication against a Computer Account
slug: 2024-01-kerberos-relay-via-coerced-auth
description: Detects potential Kerberos relay attacks by identifying coercion attempts followed by authentication events using a target server's computer account, originating from a different host, indicating an attacker has captured and relayed Kerberos authentication material to execute code on behalf of the compromised system.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kerberos
  - relay
  - credential_access
  - windows
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1187
    technique_name: Forced Authentication
cves:
  - id: CVE-2025-33073
    cvss: 8.8
    epss: 0.4924
references:
  - https://github.com/p0dalirius/windows-coerced-authentication-methods
  - https://www.thehacker.recipes/a-d/movement/mitm-and-coerced-authentications
  - https://www.synacktiv.com/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025
  - https://blog.redteam-pentesting.de/2025/reflective-kerberos-relay-attack/
  - https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
  - https://github.com/CICADA8-Research/RemoteKrbRelay/blob/main/README.md
  - https://github.com/Orange-Cyberdefense/ocd-mindmaps/blob/main/excalimap/mindmap/ad/authenticated.md
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/credential_access_dollar_account_relay_kerberos.toml
rules:
  - title: Potential Kerberos Relay Attack - Coerced Authentication Attempt
    description: Detects file access events indicating potential coerced authentication attempts against common named pipes.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1187
    data_sources:
      - file_event
      - windows
  - title: Potential Kerberos Relay Attack - Authentication from Different IP
    description: Detects Kerberos authentication events originating from a different IP address than the target server.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1187
    data_sources:
      - process_creation
      - windows
  - title: Potential Kerberos Relay Attack - Failed Authentication from Different IP
    description: Detects Kerberos authentication events (failed) originating from a different IP address than the target server.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1187
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This detection identifies potential Kerberos relay attacks targeting Windows systems. The attack involves coercing a target server to authenticate to an attacker-controlled system, which then relays the authentication to another service. The initial coercion leverages commonly abused named pipes like Spoolss, netdfs, and lsarpc. By capturing and relaying the Kerberos authentication, attackers can impersonate the target server and potentially execute code with elevated privileges. This activity is often associated with lateral movement and privilege escalation within a Windows domain. The detection focuses on the sequence of events, specifically a file access event (5145) against a named pipe, followed by a Kerberos authentication event (4624/4625) originating from a different IP address. Defenders should be aware that successful exploitation may lead to full domain compromise.

## Attack Chain

1. Attacker compromises a machine within the target network.
2. Attacker initiates a coerced authentication attempt against a target server, triggering a file access event (Event ID 5145) on the target. This leverages a named pipe such as Spoolss, netdfs, lsarpc, lsass, netlogon, samr, efsrpc, FssagentRpc, eventlog, winreg, srvsvc, dnsserver, dhcpserver or WinsPipe.
3. The target server attempts to authenticate to the attacker-controlled machine.
4. The attacker relays the Kerberos authentication attempt to a service on another server, impersonating the target server.
5. A Kerberos authentication event (Event ID 4624 or 4625) is generated, indicating a network logon attempt using Kerberos. The account used ends with '$', signifying a computer account.
6. The source IP address of the authentication event is different from the target server's IP address, indicating the authentication attempt originated from a different host.
7. If successful (Event ID 4624), the attacker gains unauthorized access to the service on the second server, impersonating the target server's computer account.
8. The attacker executes commands or performs actions on the compromised service, potentially leading to data exfiltration, system compromise, or further lateral movement.

## Impact

A successful Kerberos relay attack can lead to a full compromise of the targeted server, potentially allowing the attacker to execute arbitrary code with SYSTEM privileges. This can result in data exfiltration, service disruption, and further lateral movement within the network. The scope of the impact depends on the privileges of the compromised computer account and the services accessible to it. Organizations that do not properly patch CVE-2025-33073 or implement SMB signing/sealing/channel binding are at higher risk.

## Recommendation

*   Deploy the Sigma rule "Potential Kerberos Relay Attack against a Computer Account" to your SIEM to detect this activity and tune for your environment.
*   Investigate any alerts generated by the Sigma rule, focusing on the sequence of events and the source IP address involved.
*   Patch CVE-2025-33073 on all affected Windows servers to prevent reflective Kerberos relay attacks.
*   Enable SMB signing or service-specific signing/sealing/channel binding on affected service tiers to mitigate relay attacks.
*   Monitor Windows Security Event Logs for Event ID 5145 (file access) and Event IDs 4624/4625 (authentication attempts) for suspicious activity.
*   Restrict coercion-prone RPC and named-pipe exposure to limit the attack surface.
