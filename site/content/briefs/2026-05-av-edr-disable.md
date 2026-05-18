---
title: Threat Actors Disabling AV and EDR Solutions
slug: 2026-05-av-edr-disable
description: Threat actors are actively disabling antivirus and EDR solutions through abusing Windows Firewall rules, uninstalling agents, and exploiting vulnerable drivers (BYOVD) to establish persistence, move laterally, and deploy ransomware undetected.
date: "2026-05-18T17:14:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - privilege-escalation
  - byovd
vendors:
  - Microsoft
  - SonicWall
  - EnCase
  - Huntress
products:
  - Defender Antivirus
  - Huntress EDR
  - SonicWall VPN
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://www.huntress.com/blog/how-attackers-disable-av-edr
rules:
  - title: Defender Exclusion Modification
    description: Detects attempts to modify Windows Defender exclusions, which can be used to impair its functionality.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Firewall Rule Creation
    description: Detects suspicious creation of Windows Firewall rules potentially used to block EDR communications.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Threat actors are increasingly focusing on impairing or disabling endpoint security controls to operate undetected within compromised environments. This activity involves techniques such as creating malicious Windows Firewall rules to block EDR communications (using tools like EDRSandblast and EDRSilencer), escalating privileges to uninstall agents, and exploiting vulnerable drivers (BYOVD) to gain kernel-mode access. The objective is to create a "dark zone" where they can establish footholds, move laterally, exfiltrate data, and deploy ransomware without visibility to IT and security teams. In early February 2026, Huntress observed threat actors deploying a sophisticated "EDR Killer" binary, abusing a revoked EnCase forensic driver. This trend signifies a shift from mere evasion to active destruction of security stacks, demanding enhanced detection and response strategies.

## Attack Chain

1. Initial Access: Threat actor gains initial access via compromised credentials (e.g., SonicWall VPN).
2. Privilege Escalation: Attempts to escalate privileges to administrator level to gain greater control over the system.
3. Disable Defender: Attempts to disable Microsoft Defender Antivirus by abusing Windows Firewall rules and creating exclusions.
4. EDR Agent Uninstall: Attempts to uninstall the EDR agent using Add/Remove Programs or command-line execution.
5. BYOVD Deployment: Drops a legitimate but vulnerable, digitally signed driver (e.g., EnCase forensic driver).
6. Kernel Exploitation: Exploits the driver vulnerability to gain kernel-mode access.
7. Process Termination: Uses kernel-mode access to terminate protected EDR processes and unhook security monitoring.
8. Lateral Movement/Impact: Establishes persistence, moves laterally, exfiltrates data, and deploys ransomware with no visibility.

## Impact

Successful disabling of AV and EDR solutions allows threat actors to operate with impunity within compromised networks. This can lead to significant data breaches, financial losses, and reputational damage. The use of BYOVD techniques, as seen in the February 2026 incident, allows attackers to bypass common endpoint security measures and establish a persistent foothold. The impact is a "dark zone" where standard security monitoring tools are ineffective, allowing attackers to achieve their objectives without detection.

## Recommendation

*   Monitor for suspicious process creation events associated with disabling or modifying Windows Defender settings (Sigma rule: Defender Exclusion Modification).
*   Detect the execution of known tools used for creating malicious firewall rules, such as those employed by EDRSandblast and EDRSilencer, using process creation logs (Sigma rule: Suspicious Firewall Rule Creation).
*   Enable driver signature enforcement and monitor for the loading of known vulnerable drivers to detect BYOVD attacks (Sysmon driver load events).
