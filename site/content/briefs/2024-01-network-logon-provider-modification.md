---
title: Network Logon Provider Registry Modification
slug: 2024-01-network-logon-provider-modification
description: Adversaries may modify the network logon provider registry to register a rogue network logon provider module for persistence and credential access by intercepting authentication credentials in clear text during user logon.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - persistence
  - registry-modification
vendors:
  - Microsoft
  - Citrix
  - Dell
  - CheckPoint
products:
  - Defender XDR
  - ICA Client
  - SARemediation
  - Endpoint Connect
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1556
    technique_name: Modify Authentication Process
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://github.com/gtworek/PSBits/tree/master/PasswordStealing/NPPSpy
  - https://docs.microsoft.com/en-us/windows/win32/api/npapi/nf-npapi-nplogonnotify
rules:
  - title: Network Logon Provider Registry Modification
    description: Detects modification of the network logon provider registry to potentially inject malicious DLLs for credential access or persistence.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - persistence
    techniques:
      - T1543
      - T1556.008
    data_sources:
      - registry_set
      - windows
  - title: Suspicious Process Modifying Network Logon Provider Registry
    description: Detects processes not typically associated with registry modifications that are modifying the network logon provider registry.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - persistence
    techniques:
      - T1543
      - T1556.008
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may modify the network logon provider registry to gain persistence or access credentials. This involves registering a rogue network logon provider module that intercepts authentication credentials in clear text during user logon. The modification of the ProviderPath key under the NetworkProvider service registry path can be indicative of this malicious activity. The registry modification is often performed by non-system accounts and the adversary will attempt to hide the malicious DLL by placing it in common directories. This technique allows adversaries to steal user credentials or maintain persistent access to the compromised system.

## Attack Chain

1.  An attacker gains initial access to a Windows system, possibly through exploiting a vulnerability or using compromised credentials.
2.  The attacker elevates privileges to obtain the necessary permissions to modify the registry.
3.  The attacker locates the registry key related to network logon providers: `HKLM\SYSTEM\CurrentControlSet\Services\*\NetworkProvider\ProviderPath`.
4.  The attacker modifies the `ProviderPath` registry value to point to a malicious DLL.
5.  The system loads the malicious DLL during the logon process.
6.  The malicious DLL intercepts user credentials in clear text.
7.  The attacker harvests the intercepted credentials.
8.  The attacker uses the harvested credentials for lateral movement or further exploitation of the network.

## Impact

A successful attack can lead to the compromise of user credentials, allowing attackers to gain unauthorized access to sensitive systems and data. Modification of the network logon provider registry enables attackers to maintain persistent access to the compromised system, even after a reboot. This can result in data breaches, financial losses, and reputational damage. The severity depends on the level of access granted to the compromised accounts and the sensitivity of the data they can access.

## Recommendation

*   Monitor registry modifications to the `HKLM\SYSTEM\CurrentControlSet\Services\*\NetworkProvider\ProviderPath` key, using the provided Sigma rule to detect suspicious changes.
*   Enable Sysmon registry event logging to capture registry modifications.
*   Regularly audit network logon providers and verify the integrity and authenticity of the registered DLLs.
*   Investigate processes modifying the registry and their associated file creation events for unknown or suspicious processes.
*   Block execution of unsigned or untrusted DLLs in the network logon provider path.
*   Deploy the Sigma rule "Network Logon Provider Registry Modification" to your SIEM and tune for your environment.
