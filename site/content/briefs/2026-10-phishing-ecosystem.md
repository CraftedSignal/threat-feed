---
title: Global Phishing-as-a-Service Ecosystem Disruption
slug: 2026-10-phishing-ecosystem
description: Microsoft disrupted a Chinese-language cybercriminal ecosystem where Storm-3119 provided illicit cloud infrastructure to Storm-2990, whose phishing kits facilitated large-scale credential theft globally.
date: "2026-10-14T16:17:32Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Storm-2990
tags:
  - phishing
  - iab
  - credential-harvesting
  - cloud-security
  - storm-2990
vendors:
  - Microsoft
  - Google
products:
  - Microsoft Cloud
  - Google Cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Threat actors purchased and used these tools and infrastructure, including phishing kits and access to compromised or fraudulent Microsoft or Google cloud environments.
    confidence_band: high
references:
  - https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/
  - https://aka.ms/YamCOGUIIronMan
  - https://www.resecurity.com/blog/article/iron-man-yamstore-powering-a-global-phishing-as-a-service-ecosystem
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Audit cloud environment for unauthorized or unfamiliar administrative accounts
      owner: SOC
      due: 24h
      evidence: Storm-3119 leverages fraudulently obtained environments
  hunt_leads:
    - lead: Search logs for mass creation of organizational workspaces or accounts in cloud tenants
      technique_id: T1566
      data_needed:
        - Cloud audit logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Storm-3119 uses automation to identify expired environment or organization names
---

Microsoft identified and disrupted a complex, interconnected cybercriminal ecosystem operating since at least January 2026. The network consists of two primary clusters: Storm-3119, an Initial Access Broker (IAB) operating the 'YAM Store' marketplace, and Storm-2990, a group of developers behind the 'CoGUI', 'Haozi', and 'Iron Man System' phishing kits. Storm-3119 leverages automation to identify and acquire fraudulent or expired cloud environments (Microsoft and Google), which are then sold via Telegram-based channels to downstream threat actors. Storm-2990 creates and markets phishing kits designed to mimic legitimate government, financial, and logistics organizations. This infrastructure has facilitated over one billion phishing attempts against more than 75,000 organizations in Japan, the United States, Australia, and India. The convergence of these entities allows even low-skill actors to launch high-volume credential theft operations by renting pre-configured, reputable cloud infrastructure.

## Attack Chain

1. Storm-3119 identifies expired or vulnerable customer organization environments within major cloud platforms.
2. Storm-3119 exploits legitimate customer information and automation to provision or take over these cloud workspaces.
3. Storm-3119 lists access to these fraudulently acquired environments on the YAM Store marketplace.
4. Downstream threat actors purchase credentials or environment access via cryptocurrency (USDT, Ethereum).
5. Threat actors deploy Storm-2990 phishing kits (CoGUI, Haozi, or Iron Man System) into the purchased cloud environments.
6. Actors distribute high-volume phishing emails and SMS messages masquerading as trusted brands.
7. Victims interact with phishing lures and are directed to credential harvesting portals.
8. Stolen credentials are collected and potentially sold for further unauthorized access or financial fraud.

## Impact

The ecosystem has enabled over one billion phishing and SMS messages targeting more than 75,000 organizations worldwide. Primary sectors impacted include healthcare, financial services, wholesale distribution, and information technology. The use of fraudulently acquired legitimate infrastructure significantly lowers the barrier to entry for attackers, increasing the volume of credential theft and subsequent fraud losses.

## Recommendation

- Monitor cloud tenant logs for suspicious new administrative accounts or unauthorized workspace provisioning, especially those associated with domains matching known organizational patterns.
- Implement strict multi-factor authentication (MFA) policies that require phishing-resistant hardware keys, as the kits target credential harvesting.
- Review cloud environment activity logs for spikes in administrative or configuration changes that deviate from established baselines for your organization's cloud tenancy.
- Educate users on the increasing prevalence of SMS-based phishing (smishing) originating from infrastructure that may appear legitimate.
- Deploy proactive email filtering to scan for phishing links that utilize compromised cloud-based file sharing or hosting services rather than known malicious domains.
