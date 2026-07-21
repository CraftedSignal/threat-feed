---
title: Midyear Assessment of Iran-Linked Cyber Threat Landscape
slug: 2026-07-iran-cyber-threat-assessment
description: SentinelOne Labs' midyear assessment highlights that Iran-linked cyber operations, involving groups like MuddyWater/Seedworm, Screening Serpens, APT42, and persona groups such as Handala, focus on persistent access, espionage, and selective disruption, often leveraging social engineering, compromised service providers, and RMM abuse, with increasing risk to operational technology environments.
date: "2026-07-21T13:03:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - iran
  - espionage
  - destructive-malware
  - social-engineering
  - operational-technology
  - rmm
  - supply-chain
  - threat-assessment
  - apt
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Screening Serpens identified six new RAT variants deployed between February and April against apparent targets in the United States, Israel, the UAE, and the wider Middle East. The campaigns continued the actor’s tailored recruitment lures.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Long-running APT42 operations have targeted journalists, researchers, NGOs, academics, activists, and government-linked individuals. One compromised cloud account holds organizational context, relationships, and internal deliberations, and can yield collection, impersonation, lateral targeting, and entry into the wider organization.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
    evidence: Check Point’s July reporting on Cavern Manticore described intrusions in which existing RMM access and compromised IT-provider environments opened paths into targets.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Screening Serpens... added AppDomainManager hijacking.
    confidence_band: med
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: Screening Serpens... added AppDomainManager hijacking.
    confidence_band: med
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
    evidence: One compromised cloud account holds organizational context, relationships, and internal deliberations, and can yield collection, impersonation, lateral targeting, and entry into the wider organization.
    confidence_band: med
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1560
    technique_name: Archive Collected Data
    evidence: Researchers identified multiple backdoors and an attempted transfer of data to commercial cloud storage.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Researchers identified multiple backdoors and an attempted transfer of data to commercial cloud storage.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1491
    technique_name: Defacement
    evidence: Three months of headlines have tracked leaks, defacements, and outages.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
    evidence: Three months of headlines have tracked leaks, defacements, and outages.
    confidence_band: med
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Destruction
    evidence: At least one recent Handala wiping script was assessed as likely AI-assisted.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Destruction
    evidence: A meaningful portion of higher-impact public activity resolves to personas of the MOIS-linked Void Manticore apparatus... a common playbook combining destructive intrusions with data publication, doxxing, and threats.
    confidence_band: high
references:
  - https://www.sentinelone.com/labs/iran-war-cyber-threat-landscape-a-midyear-assessment-on-what-matters/
---

This midyear assessment from SentinelOne Labs updates the understanding of Iran's cyber threat landscape, identifying a complex ecosystem of state-linked entities including MOIS, the IRGC Intelligence Organization, and the IRGC Cyber-Electronic Command, alongside affiliated personas and opportunists. These diverse groups pursue distinct missions ranging from persistent espionage and access enablement (MuddyWater/Seedworm, APT34) to destructive and coercive operations via public personas like Handala (Void Manticore). Iranian actors prioritize gaining "access optionality," where initial footholds for intelligence collection can be repurposed for disruption or other strategic objectives as political tasking evolves. Targeting includes government entities, critical infrastructure (OT environments with internet-facing PLCs, weak credentials, poor remote access governance), financial institutions, and high-trust individuals through social engineering (APT42, Screening Serpens), with activity often leveraging compromised service providers and Remote Monitoring and Management (RMM) pathways (Cavern Manticore). Generative AI is noted as an efficiency multiplier for tasks like coding and lure development.

## Attack Chain

1. Iranian threat actors gain initial access through targeted social engineering (e.g., recruitment-themed lures by Screening Serpens or high-trust individual targeting by APT42) or by exploiting compromised service provider accounts and RMM pathways (Cavern Manticore).
2. Attackers establish a persistent foothold by deploying custom backdoors and Remote Access Trojans (RATs) like those used by MuddyWater/Seedworm, or by abusing legitimate administrative tools.
3. Persistence mechanisms are created or modified, including techniques such as AppDomainManager hijacking (Screening Serpens) to maintain control over compromised systems.
4. Adversaries perform credential access by compromising user accounts, particularly cloud service accounts (APT42), or leveraging existing administrative privileges within breached service provider environments.
5. Lateral movement and internal reconnaissance are conducted using compromised accounts and RMM access to navigate target networks or pivot into customer networks via compromised service providers.
6. Data collection focuses on sensitive information, which is then exfiltrated to attacker-controlled infrastructure or commercial cloud storage (e.g., as observed with MuddyWater/Seedworm activity).
7. For espionage-focused groups (APT34, Screening Serpens), this involves ongoing collection and exfiltration of political, diplomatic, and telecommunications intelligence.
8. Destructive or coercive operations are executed by persona groups (e.g., Handala, Homeland Justice, Karma/KarmaBelow80), which may involve data wiping (potentially AI-assisted scripts), data publication, doxxing, and intimidation campaigns.

## Impact

The impact of Iran-linked cyber activity is broad, extending from long-term espionage and data exfiltration to disruptive and coercive operations. Organizations targeted include U.S. banks, airports, non-profits, and defense/aerospace suppliers, as well as government infrastructure in the Middle East. If successful, these attacks can lead to significant intelligence loss, compromise of sensitive data, and reputational damage through data leaks and doxxing. The "access optionality" strategy means that initial espionage footholds can be rapidly converted into disruptive attacks, causing operational outages and financial losses. Targeting of Operational Technology (OT) environments, especially those with internet-facing PLCs and weak security, risks real disruption to critical services, though the full extent of process manipulation through interface access alone requires further evidence.

## Recommendation

* Implement robust multi-factor authentication for all user and administrative accounts, especially for cloud services and RMM tools, to mitigate initial access and lateral movement techniques employed by APT42 and Cavern Manticore.
* Monitor process creation logs for the deployment and execution of unknown RATs and backdoors, particularly those associated with MuddyWater/Seedworm activity.
* Enable network connection logging to identify unusual outbound data transfers to commercial cloud storage or attacker infrastructure, as seen with MuddyWater/Seedworm.
* Regularly review and audit RMM access and service provider connections to identify and revoke any unauthorized or dormant access used by groups like Cavern Manticore.
* Deploy advanced endpoint detection and response (EDR) solutions to detect and prevent persistence mechanisms like AppDomainManager hijacking, as described for Screening Serpens.
* Conduct regular security awareness training emphasizing social engineering techniques, specifically recruitment lures and high-trust impersonation, to reduce the effectiveness of APT42 and Screening Serpens initial access tactics.
* Harden Operational Technology (OT) environments by eliminating internet-facing PLCs, enforcing strong password policies, and restricting remote access to prevent opportunistic targeting by IRGC-CEC affiliated groups.
