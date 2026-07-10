---
title: NLTEST.EXE Used for Domain Trust Discovery
slug: 2024-01-nltest-domain-trust-discovery
description: Adversaries may use `nltest.exe` to enumerate domain trusts, gaining insight into trust relationships and the state of Domain Controller replication within a Windows NT Domain, potentially leading to lateral movement.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - discovery
  - windows
  - nltest
  - domain-trust
vendors:
  - Microsoft
products:
  - Windows Server
  - Active Directory
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1482
    technique_name: Domain Trust Discovery
references:
  - https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11)
  - https://redcanary.com/blog/how-one-hospital-thwarted-a-ryuk-ransomware-outbreak/
rules:
  - title: Detect Suspicious NLTEST Execution for Domain Trust Discovery
    description: Detects the execution of `nltest.exe` with command-line arguments indicative of domain trust discovery activities.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1018
      - T1482
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious NLTEST Execution for Domain Trust Discovery via Sysmon
    description: Detects the execution of `nltest.exe` with command-line arguments indicative of domain trust discovery activities using Sysmon.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1018
      - T1482
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The `nltest.exe` utility is a command-line tool used for managing and troubleshooting Windows NT Domains. While legitimate domain administrators may occasionally use `nltest.exe` for information gathering, adversaries can leverage it to enumerate domain trusts and understand trust relationships within a target environment. This information can be critical for planning subsequent attack stages, such as lateral movement. This activity is most relevant in environments with older Windows Server versions (pre-2012), as newer systems have alternative tools. The activity can also be indicative of attackers trying to identify ways to move laterally within the network or gain access to sensitive resources.

## Attack Chain

1.  The adversary gains initial access to a compromised host within the target network.
2.  The attacker executes `nltest.exe` with specific arguments to enumerate domain trusts. Example arguments include `/DOMAIN_TRUSTS`, `/PARENTDOMAIN`, and `/DCLIST`.
3.  `nltest.exe` queries the Active Directory domain controller for information about trust relationships.
4.  The domain controller responds with a list of trusted domains and their attributes.
5.  The attacker parses the output of `nltest.exe` to identify potential targets for lateral movement.
6.  The attacker uses discovered trust relationships to attempt authentication or access resources in other domains.
7.  If successful, the attacker moves laterally to other systems within the trusted domains.
8.  The ultimate goal is to gain access to sensitive data, escalate privileges, or disrupt services.

## Impact

Successful enumeration of domain trusts can provide attackers with valuable information about the network topology and trust relationships, enabling them to move laterally within the environment. This can lead to unauthorized access to sensitive data, privilege escalation, and potential disruption of critical services. The impact is amplified in environments with complex trust configurations or older Windows Server versions, where `nltest.exe` remains a relevant tool for domain management.

## Recommendation

*   Monitor process creation events for `nltest.exe` with command-line arguments related to domain trust discovery (e.g., `/DOMAIN_TRUSTS`, `/PARENTDOMAIN`, `/DCLIST`) using the Sigma rule "Detect Suspicious NLTEST Execution for Domain Trust Discovery".
*   Investigate any instances of `nltest.exe` execution originating from unusual or non-administrative user accounts.
*   Audit and review existing domain trust configurations to identify and remediate any overly permissive trust relationships.
*   Consider disabling or restricting the use of `nltest.exe` on non-administrative workstations where it is not required.
*   Enable Windows Security Event Logging, Sysmon or other endpoint detection to capture process creation events and command-line arguments for effective detection.
