---
title: Windows Privilege Escalation via Secondary Logon Service
slug: 2024-01-secondary-logon-privilege-escalation
description: The rule identifies process creation with alternate credentials, which can be used for privilege escalation, by detecting successful logins via the Secondary Logon service (seclogon) from a local source IP address (::1), followed by process creation using the same TargetLogonId.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - windows
  - access-token-manipulation
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1134
    technique_name: Access Token Manipulation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1134
    technique_name: Access Token Manipulation
references:
  - https://attack.mitre.org/techniques/T1134/002/
rules:
  - title: Process Creation via Secondary Logon
    description: Detects process creation with alternate credentials via the Secondary Logon service.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1134.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Secondary Logon Authentication Events
    description: Detects successful authentication events via the Secondary Logon service.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1134.002
    data_sources:
      - authentication
      - windows
rules_count: 2
---

The Secondary Logon service in Windows allows users to run processes with different credentials, which can be abused to escalate privileges and bypass access controls. This technique involves an adversary successfully authenticating via the seclogon service, typically from the local host, then spawning a new process under the context of this newly acquired, potentially elevated, token. The detection focuses on identifying successful seclogon authentications where the source IP is the loopback address (::1), tied to subsequent process creations sharing the same logon ID. This is a common method for local privilege escalation.

## Attack Chain

1.  An attacker gains initial access to a Windows system through various means.
2.  The attacker attempts to leverage the Secondary Logon service (seclogon) to create a new process with elevated privileges.
3.  A successful logon event is generated, with the LogonProcessName indicating "seclogo*" and source IP address of "::1", and event ID indicating a successful login.
4.  svchost.exe is used as the process responsible for calling seclogon.
5.  The system assigns a TargetLogonId to the new logon session.
6.  The attacker creates a new process, specifying the TargetLogonId obtained from the previous step.
7.  The new process is launched with the security context of the alternate credentials, potentially granting the attacker elevated privileges.
8.  The attacker performs malicious actions using the newly elevated privileges, such as accessing sensitive data or installing malware.

## Impact

Successful exploitation allows attackers to perform actions with elevated privileges, potentially leading to complete system compromise. An attacker can bypass access controls and gain unauthorized access to sensitive resources. If successful, this can lead to data theft, system compromise, or the installation of persistent backdoors.

## Recommendation

*   Enable Audit Logon to generate the events required for the rules in this brief (reference: Setup section in the source).
*   Deploy the "Process Creation via Secondary Logon" Sigma rule to your SIEM and tune for your environment to detect potential privilege escalation attempts (reference: Sigma rules below).
*   Monitor for svchost.exe processes initiating secondary logon events from the local loopback address (::1) as an indicator of local privilege escalation.
