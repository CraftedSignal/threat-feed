---
title: PowerShell Kerberos Ticket Dumping via LSA Authentication Package Access
slug: 2024-01-26-powershell-kerberos-dump
description: Detection of PowerShell scripts attempting to dump Kerberos tickets from memory by accessing LSA authentication packages, potentially leading to credential access and lateral movement.
date: "2024-01-26T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - kerberos
  - powershell
  - windows
vendors:
  - Microsoft
products:
  - PowerShell
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://github.com/MzHmO/PowershellKerberos/blob/main/dumper.ps1
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/credential_access_posh_kerb_ticket_dump.toml
rules:
  - title: PowerShell Kerberos Ticket Dump - LsaCallAuthenticationPackage
    description: Detects PowerShell scripts using LsaCallAuthenticationPackage to access Kerberos authentication packages and retrieve tickets.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - process_creation
      - windows
  - title: PowerShell Kerberos Ticket Dump - LsaLookupAuthenticationPackage
    description: Detects PowerShell scripts using LsaLookupAuthenticationPackage to find Kerberos packages and retrieve tickets.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief focuses on detecting PowerShell scripts designed to extract Kerberos tickets from memory. Attackers use these scripts to gain unauthorized access to credentials, which can then be leveraged for lateral movement within a network. The scripts achieve this by interacting with the Local Security Authority (LSA) and accessing Kerberos authentication packages. The observed PowerShell scripts utilize specific Kerberos ticket message types or dynamic Kerberos package lookup to enumerate and retrieve tickets. This behavior is often associated with post-exploitation activity, where attackers are attempting to escalate privileges or move laterally within a compromised environment. Defenders should monitor PowerShell activity for these patterns, as successful Kerberos ticket dumping can lead to significant security breaches. The scripts are not associated with any specific campaign or version.

## Attack Chain

1. An attacker gains initial access to a Windows system (e.g., through phishing or exploiting a vulnerability).
2. The attacker executes a PowerShell script.
3. The PowerShell script uses `LsaCallAuthenticationPackage` to interact with the LSA.
4. The script attempts to retrieve Kerberos tickets by using functions like `KerbRetrieveEncodedTicketMessage`, `KerbQueryTicketCacheMessage`, `KerbQueryTicketCacheExMessage`, or `KerbRetrieveTicketMessage`.
5. Alternatively, the script uses `LsaLookupAuthenticationPackage` to dynamically locate the Kerberos package.
6. The script may then decrypt the ticket data using `KerbDecryptDataMessage`.
7. The script may attempt to serialize or export the extracted tickets to a file.
8. The attacker uses the dumped Kerberos tickets to impersonate users or services, gaining unauthorized access to resources and facilitating lateral movement.

## Impact

Successful exploitation allows attackers to steal Kerberos tickets from memory. The attacker can then use these tickets to impersonate legitimate users or services, enabling them to move laterally within the network, access sensitive data, and potentially compromise critical systems. The impact includes unauthorized access to resources, data breaches, and potentially a complete compromise of the targeted Windows domain.

## Recommendation

*   Enable PowerShell Script Block Logging to capture the malicious script content (as mentioned in the "Setup" section).
*   Deploy the Sigma rule "PowerShell Kerberos Ticket Dump" to detect scripts exhibiting Kerberos ticket dumping behavior.
*   Investigate any alerts triggered by the Sigma rule, focusing on the reconstructed script block content and process lineage as outlined in the "Triage and analysis" section.
*   Monitor for file creation events related to ticket material exports (e.g., ".kirbi" files) to identify potential ticket dumping activity.
*   Review authentication events (event codes 4624, 4625, 4648) to identify suspicious logins originating from compromised systems.
