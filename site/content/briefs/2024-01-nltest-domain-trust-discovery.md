---
title: NLTEST.EXE Used for Domain Trust Discovery
slug: 2024-01-nltest-domain-trust-discovery
description: Adversaries may use the `nltest.exe` command-line utility to enumerate domain trusts and gain insight into trust relationships to facilitate lateral movement within a Microsoft Windows NT Domain.
date: "2024-01-11T17:49:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - discovery
  - domain trust
  - lateral movement
  - windows
vendors:
  - Microsoft
products:
  - Windows NT Domain
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
  - title: Detect NLTEST.EXE for Domain Trust Discovery
    description: Detects the execution of nltest.exe with arguments used to enumerate domain trusts.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1018
      - T1482
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious NLTEST.EXE Usage
    description: Detects suspicious usage of nltest.exe with uncommon arguments for domain information gathering.
    platform: sigma
    severity: low
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

The `nltest.exe` utility is a command-line tool used to manage and troubleshoot Windows NT domains. While legitimate domain administrators may use this utility for information gathering, adversaries can also abuse it to enumerate domain trusts and gain insight into trust relationships, which exposes the state of Domain Controller (DC) replication within a Windows NT Domain. This activity is more suspicious in environments with Windows Server 2012 and newer, where its usage is less common for legitimate purposes. Attackers can leverage this information to facilitate lateral movement and other malicious activities within the network.

## Attack Chain

1. An attacker gains initial access to a compromised host within the target environment.
2. The attacker executes `nltest.exe` with specific arguments such as `/DOMAIN_TRUSTS`, `/DCLIST:*`, `/DCNAME:*`, `/DSGET*`, `/LSAQUERYFTI:*`, `/PARENTDOMAIN`, or `/BDC_QUERY:*` to enumerate domain trusts.
3. The `nltest.exe` utility queries the Active Directory to gather information about domain trusts, domain controllers, and other domain-related information.
4. The attacker parses the output of `nltest.exe` to identify trust relationships, domain controllers, and other relevant information about the domain infrastructure.
5. The attacker uses the gathered information to map out potential lateral movement paths within the environment.
6. The attacker leverages discovered trust relationships to authenticate to other domains or resources.
7. The attacker moves laterally to other systems or domains, leveraging the discovered trust relationships and compromised credentials.
8. The attacker establishes persistence and continues to perform malicious activities, such as data exfiltration or ransomware deployment.

## Impact

Successful enumeration of domain trusts via `nltest.exe` can provide attackers with valuable information to facilitate lateral movement and escalate privileges within a Windows NT Domain. This can lead to the compromise of sensitive data, disruption of critical services, and ultimately, a complete takeover of the affected environment. While the specific number of victims and sectors targeted are unknown, the impact can be significant for organizations relying on Active Directory for authentication and authorization.

## Recommendation

*   Monitor process execution for `nltest.exe` with command-line arguments indicative of domain trust discovery, using the provided Sigma rule.
*   Investigate any instances of `nltest.exe` execution, especially when initiated by non-administrative users or from unusual locations, as identified by the Sigma rule.
*   Enable Sysmon process creation logging to capture the necessary process execution data for the provided Sigma rule.
*   Review and restrict the use of `nltest.exe` to authorized personnel only.
