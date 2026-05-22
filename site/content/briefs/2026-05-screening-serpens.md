---
title: Screening Serpens APT Targets Tech and Defense Sectors with New RATs
slug: 2026-05-screening-serpens
description: The Iranian APT group Screening Serpens targeted the tech and defense sectors in the U.S., Israel, and the UAE between February and April 2026, deploying six new RAT variants from the MiniUpdate and MiniJunk V2 malware families, using tailored social engineering lures and AppDomainManager hijacking.
date: "2026-05-22T13:09:06Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Screening Serpens
tags:
  - Screening Serpens
  - APT
  - Iran
  - RAT
  - MiniUpdate
  - MiniJunk
  - DLL Sideloading
  - AppDomainManager
  - Cyberespionage
vendors:
  - Microsoft
  - Azure
products:
  - MiniUpdate
  - MiniJunk
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1574
    technique_name: Hijack Execution Flow
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/
rules:
  - title: Detects MiniUpdate RAT Deployment via DLL Sideloading
    description: Detects DLL sideloading of 'UpdateChecker.dll', a component of the MiniUpdate RAT, by monitoring for process creation events where the DLL is loaded from an unusual path.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1574.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Azure Subdomain
    description: Detects connections to suspicious Azure subdomain.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Unit 42 researchers observed cyberattacks by Screening Serpens, an Iran-nexus APT group, targeting entities in the U.S., Israel, and the UAE, as well as two additional Middle Eastern entities, between February and April 2026. The group deployed six new remote access Trojan (RAT) variants, categorized into the MiniUpdate and MiniJunk V2 malware families. Screening Serpens primarily targets technology sector professionals, using tailored social engineering lures that impersonate trusted brands and hiring platforms. The most critical evolution in the group’s recent campaign uses a technique called AppDomainManager hijacking. These campaigns align closely with the regional conflict that started in the Middle East on Feb. 28, 2026.

## Attack Chain

1.  **Initial Access:** The attack begins with highly tailored spear-phishing emails impersonating trusted brands and hiring platforms, specifically targeting technical personnel. These emails contain a ZIP archive (e.g., initial archive file 44f4f7aca7f1d9bfdaf7b3736934cbe19f851a707662f8f0b0c49b383e054250), often mimicking legitimate corporate job applications by including specific job IDs.
2.  **Delivery:** The ZIP archive contains a nested payload archive (e.g., Hiring Portal.zip hash 332ba2f0297dfb1599adecc3e9067893e7cf243aa23aedce4906a4c480574c17) packaged alongside PDF documents. These PDFs are crafted job requisitions targeting high-level IT and engineering roles.
3.  **Execution:** The target is tricked into extracting the nested archive, believing they are accessing an application portal or a technical assessment. DLL sideloading is used for execution within the extracted files.
4.  **AppDomainManager Hijacking:** The attackers employ AppDomainManager hijacking. This technique manipulates the initialization phase of .NET applications to proactively disable the application’s own security mechanisms via a legitimate configuration file.
5.  **Payload Deployment:** The disabled security in these apps leaves the targeted entities vulnerable to the deployed multi-functional RATs (MiniUpdate or MiniJunk V2). For example, UpdateChecker.dll (0db36a04d304ad96f9e6f97b531934594cd95a5cea9ff2c9af249201089dc864) is deployed.
6.  **Command and Control:** The RAT establishes command and control (C2) communication with attacker-controlled infrastructure (e.g., themesmanangers.azurewebsites[.]net) over HTTP/HTTPS.
7.  **Data Exfiltration:** The RAT exfiltrates sensitive information from the compromised system. The MiniUpdate variant, in particular, has the ability to exfiltrate files in chunks.
8.  **Espionage:** The attacker gains access to sensitive information, enabling cyberespionage aligned with Iranian intelligence objectives, particularly targeting aerospace, defense manufacturing, and telecommunications organizations.

## Impact

Screening Serpens' campaigns targeted entities in the U.S., Israel, and the UAE, as well as two additional Middle Eastern entities, potentially compromising sensitive data and intellectual property. The targeted sectors include aerospace, defense manufacturing, and telecommunications. If successful, these attacks can lead to significant financial losses, reputational damage, and the compromise of national security interests. The campaigns affected organizations in multiple countries and highlight the increasing technical capabilities and operational resilience of Screening Serpens.

## Recommendation

*   Block the C2 domains listed in the IOC table at the DNS resolver to prevent communication with attacker infrastructure.
*   Monitor process creation events for DLL sideloading activity, especially from unusual locations (e.g., user profiles) to identify potential MiniUpdate/MiniJunk infections. Deploy the Sigma rule `Detects MiniUpdate RAT Deployment via DLL Sideloading` to identify DLL sideloading.
*   Enable enhanced .NET security logging to detect AppDomainManager hijacking attempts.
*   Deploy the Sigma rule `Detect Suspicious Azure Subdomain` to detect use of azurewebsites domains that may be malicious.
*   Implement robust email security controls and user awareness training to prevent successful spear-phishing attacks, especially those impersonating trusted brands and job opportunities.
*   Monitor network connections for processes communicating with the listed URLs in the IOC table to identify potential malicious network activity.
