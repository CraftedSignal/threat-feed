---
title: Disruption of Integrity Technology Group Hacking Tools
slug: 2026-10-chinese-hacking-tools-disruption
description: The US government disrupted infrastructure supporting Integrity Technology Group tools MicroScan and FishHub, which Chinese state-sponsored actors, including Flax Typhoon, used to compromise critical infrastructure.
date: "2026-10-09T08:39:25Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Flax Typhoon
  - Ethereal Panda
tags:
  - state-sponsored
  - intelligence-disruption
  - critical-infrastructure
  - espionage
vendors:
  - Apache
  - Juniper
  - Jenkins
  - OpenSSL
  - Oracle
  - Rejetto
  - WordPress
  - Microsoft
products:
  - Struts
  - ScreenOS
  - Jenkins
  - OpenSSL
  - WebLogic Server
  - WordPress
  - Exchange Server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566.001
    technique_name: Spearphishing Attachment
    evidence: FishHub has enabled network intrusions via spear phishing.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: They deployed VPN tools such as SoftEther for persistence.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
    evidence: Built by Integrity Technology Group (Integrity Tech), MicroScan has been used for vulnerability scanning.
    confidence_band: high
references:
  - https://www.securityweek.com/us-disrupts-chinese-state-sponsored-hacking-tools/
iocs:
  - type: domain
    value: c0cc.cc
  - type: domain
    value: 98aicai.com
  - type: domain
    value: 98aicode.com
  - type: domain
    value: outlook3650.com
  - type: domain
    value: youtubecard.com
  - type: domain
    value: linkedinns.net
ioc_counts:
  domain: 6
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
  immediate_actions:
    - action: Block listed C2 domains on DNS and web proxy.
      owner: SOC
      due: 24h
      evidence: Source explicitly lists seized domains used by threat actors.
  mitigation_plan:
    - priority: immediate
      action: Patch internet-facing services including Apache Struts, WebLogic, and WordPress.
      owner: IT Operations
      addresses: Known vulnerability scanning targets of MicroScan tool.
      evidence: Advisory lists these services as primary targets for toolset.
---

The United States government has announced the seizure of domains associated with Integrity Technology Group (Integrity Tech), an entity previously sanctioned for providing cyber tools to Chinese state-sponsored threat actors. The disruption targeted two primary tools: MicroScan, a Python-based vulnerability scanner containing over 1,300 penetration testing scripts, and FishHub, a platform enabling remote access and data exfiltration. These tools have been active since 2017, targeting a broad range of technologies including Apache Struts, Juniper ScreenOS, Jenkins, Oracle WebLogic, and WordPress. Flax Typhoon and other associated APTs leveraged these tools alongside IoT botnets to conduct large-scale reconnaissance and persistent intrusion operations against critical infrastructure in the US, Japan, Taiwan, and Europe. Defenders should note that these actors continue to utilize custom scripts for email exfiltration and Active Directory data theft.

## Attack Chain

1. Initial reconnaissance performed using MicroScan via an IoT botnet to identify vulnerable services (e.g., Apache Struts, WebLogic, WordPress).
2. Initial access achieved through spear-phishing campaigns or exploitation of discovered vulnerabilities in internet-facing services.
3. Deployment of SoftEther VPN tools on compromised assets to establish persistent, remote access to internal networks.
4. Credential harvesting conducted using tools like EBurst against Microsoft Exchange servers.
5. Internal reconnaissance and lateral movement facilitated by tools such as Fscan and Nmap.
6. Data collection and sensitive information extraction from Active Directory using the utility DC.ex.
7. Final exfiltration of email databases and proprietary files using custom utilities like office-cli and PHP script Curlc4.txt.

## Impact

The campaign targeted critical infrastructure entities including power companies, government organizations, law enforcement agencies, healthcare systems, and universities across Southeast Asia, Japan, and Poland. Documented impacts include mass email data exfiltration, theft of sensitive Active Directory data, and unauthorized persistence within the networks of critical NGOs and government institutions. The use of IP-restricted access mechanisms for exfiltrated data highlights the long-term impact on victim privacy and operational security.

## Recommendation

Prioritize hunting for the specific tools and infrastructure associated with Integrity Tech in your environment.
- Block the seized C2 domains listed in the IOC table at the network perimeter.
- Review network logs for outbound connections to these identified domains.
- Hunt for the presence of the specific exfiltration utilities mentioned (office-cli, Curlc4.txt) and the DC.ex utility on high-value targets.
- Audit internet-facing services (Apache Struts, Jenkins, Oracle WebLogic, WordPress) for signs of unauthorized scanning or reconnaissance patterns described in the advisory.
- Monitor for the deployment of SoftEther VPN software, as it is a favored tool for persistence in this campaign.
