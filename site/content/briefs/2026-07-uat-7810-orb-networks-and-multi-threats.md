---
title: UAT-7810 Expands ORB Networks with New Malware; ARToken Phishing-as-a-Service and Device Vulnerabilities Highlighted
slug: 2026-07-uat-7810-orb-networks-and-multi-threats
description: The China-nexus threat actor UAT-7810 is expanding its Operational Relay Box (ORB) networks by exploiting known vulnerabilities in unpatched Ruckus and ASUS routers to deploy custom backdoors like LONGLEASH and DOGLEASH, while other threats include the ARToken Phishing-as-a-Service platform targeting Microsoft 365, critical flaws in AirDrop/Quick Share, and a backdoor in Tenda router firmware.
date: "2026-07-09T18:01:50Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - UAT-7810
tags:
  - China-nexus
  - APT
  - router-exploitation
  - ORB-network
  - backdoor
  - phishing-as-a-service
  - credential-theft
  - data-exfiltration
  - denial-of-service
  - n-day-vulnerability
  - active-exploitation
vendors:
  - Ruckus
  - ASUS
  - Apple
  - Google
  - Tenda
  - Microsoft
products:
  - Ruckus routers
  - ASUS routers
  - AirDrop
  - Quick Share
  - Tenda router firmware
  - Microsoft 365
affected_os:
  - macOS
  - iOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The group exploits known vulnerabilities in unpatched Ruckus and ASUS routers to deploy new tools
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: The group exploits known vulnerabilities...to deploy new tools, including the upgraded "LONGLEASH" and "DOGLEASH" backdoors.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1572
    technique_name: Protocol Tunneling
    evidence: UAT-7810 builds these covert networks to provide infrastructure for other APT groups...ORB networks create a massive blind spot. They allow secondary threat actors to mask their origins and route malicious traffic through seemingly innocuous nodes.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
    evidence: By compromising edge devices like wireless routers, UAT-7810 builds a highly evasive, decentralized proxy network that easily bypasses traditional perimeter defenses.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: A hidden authentication backdoor has been found in multiple Tenda router firmware versions, potentially allowing an attacker to gain administrative access to the device's web management panel.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1528
    technique_name: Steal Web Session Cookie
    evidence: 'ARToken: Inside an EvilTokens affiliate panel targeting Microsoft 365...The ARToken panel exposes 80+ API endpoints for device code phishing, Primary Refresh Token persistence, email access...'
    confidence_band: med
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1566
    technique_name: Phishing
    evidence: Talos has identified "ARToken," a phishing-as-a-service platform that targets Microsoft 365. The ARToken panel exposes 80+ API endpoints for device code phishing...
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Defacement
    evidence: AirDrop and Quick Share flaws let nearby attackers trigger crashes and bypass checks
    confidence_band: med
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
    evidence: The ARToken panel exposes 80+ API endpoints for device code phishing, Primary Refresh Token persistence, email access, BEC operations, and SharePoint exfiltration.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: The ARToken panel exposes 80+ API endpoints for device code phishing, Primary Refresh Token persistence, email access, BEC operations, and SharePoint exfiltration.
    confidence_band: high
references:
  - https://blog.talosintelligence.com/winning-54-of-the-time/
  - https://blog.talosintelligence.com/uat-7810/
  - https://techcrunch.com/2026/07/06/the-first-ai-run-ransomware-attack-still-needed-a-human/
  - https://thehackernews.com/2026/06/airdrop-and-quick-share-flaws-let.html
  - https://www.bleepingcomputer.com/news/security/hidden-backdoor-in-tenda-router-firmware-grants-admin-access/
  - https://blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/
iocs:
  - type: hash_sha256
    value: 9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507
  - type: hash_md5
    value: 2915b3f8b703eb744fc54c81f4a9c67f
  - type: hash_sha256
    value: 621c6d42409e8aa423684827b4375a35684c71c600f2dd9101f235e8ec633488
  - type: hash_md5
    value: 9b512ba139304c247ddd3d2c4b9179fd
  - type: hash_sha256
    value: 9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f
  - type: hash_md5
    value: 38de5b216c33833af710e88f7f64fc98
  - type: hash_sha256
    value: afc8a00883a4ea07df2dc1d4ed02f8a23b35c9456413b438a2d9ce3ae5076638
  - type: hash_md5
    value: cc4d231df34e57f59eb970353c7d9de2
ioc_counts:
  hash_md5: 4
  hash_sha256: 4
---

Cisco Talos reports that the China-nexus threat actor UAT-7810 is actively expanding its Operational Relay Box (ORB) networks, which began around 2026, by exploiting known vulnerabilities in unpatched Ruckus and ASUS routers. This campaign involves the deployment of new custom malware, specifically the upgraded "LONGLEASH" and "DOGLEASH" backdoors, to establish covert infrastructure used by other APT groups to mask their origins and launch attacks against high-value targets. This brief also highlights other significant threats: the "ARToken" Phishing-as-a-Service platform targeting Microsoft 365 for credential theft and data exfiltration, critical vulnerabilities in Apple's AirDrop and Google's Quick Share allowing nearby attackers to crash services, and a hidden authentication backdoor discovered in Tenda router firmware granting administrative access. The continuous development of sophisticated, multi-platform tools by UAT-7810 underscores their investment in resilient and evasive infrastructure.

## Attack Chain

1. UAT-7810 identifies and exploits known, unpatched vulnerabilities in internet-facing Ruckus and ASUS routers.
2. Upon successful exploitation, the threat actor gains unauthorized access and deploys custom malware, including "LONGLEASH" and "DOGLEASH" backdoors, onto the compromised router.
3. The compromised routers are integrated into UAT-7810's Operational Relay Box (ORB) network, establishing a covert, decentralized proxy infrastructure.
4. The ORB network is then utilized to mask the true origin of subsequent malicious traffic, significantly enhancing attacker anonymity and evasion.
5. Malicious traffic from various APT groups is routed through these seemingly innocuous ORB nodes, bypassing traditional perimeter defenses.
6. UAT-7810 provides this resilient infrastructure to other APT groups, enabling them to launch sophisticated, evasive attacks.
7. These secondary threat actors leverage the ORB network to target high-value organizations for intelligence gathering, espionage, or other objectives.

## Impact

The expansion of UAT-7810's ORB networks creates significant blind spots for defenders, allowing other APTs to mask their origins and route malicious traffic through seemingly benign infrastructure. This directly bypasses traditional perimeter defenses, making attribution and mitigation extremely difficult. If successful, organizations face severe consequences including data exfiltration, persistent unauthorized access, and potential further compromise from other APTs leveraging this infrastructure. Additionally, the ARToken Phishing-as-a-Service platform threatens Microsoft 365 users with widespread credential theft, email access, BEC operations, and SharePoint exfiltration, while AirDrop and Quick Share flaws can lead to denial-of-service on user devices, and the Tenda router backdoor grants full administrative control over network edge devices.

## Recommendation

* Ensure all edge devices, specifically Ruckus and ASUS routers, are fully patched against known vulnerabilities that UAT-7810 exploits.
* Monitor network traffic for unusual proxying behavior or unauthorized connections on devices that typically lack complex services, leveraging insights from the Talos blog post on UAT-7810.
* Block the provided malware SHA256 hashes (e.g., `9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507`) at endpoint security solutions and network gateways.
* Implement robust phishing detection and user education against sophisticated campaigns like those facilitated by the ARToken platform, focusing on Microsoft 365 environments.
* Apply security updates to Apple and Google devices to mitigate AirDrop and Quick Share vulnerabilities that could lead to crashes.
* Verify firmware integrity and update Tenda routers to patched versions or consider alternative devices if no fix is available, given the hidden backdoor allows administrative access.
