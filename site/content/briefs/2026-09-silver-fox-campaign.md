---
title: Silver Fox Counterfeit Installer Campaign
slug: 2026-09-silver-fox-campaign
description: An active campaign impersonates legitimate software vendors via look-alike websites to distribute dynamically generated malicious installers that evade detection and establish persistent access.
date: "2026-09-02T05:58:36Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Silver Fox
tags:
  - phishing
  - malware
  - initial-access
  - silver-fox
  - china
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The entry point is a fraudulent software-download website that spoofs a legitimate vendor.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Once executed, the malicious installers deploy malware that establishes persistence
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: deploy malware that establishes persistence
    confidence_band: high
iocs:
  - type: domain
    value: pc-razerzone.com.cn
  - type: domain
    value: gehie246.com
ioc_counts:
  domain: 2
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block all domains listed in the IOC table at the network perimeter.
      owner: SOC
      due: 24h
      evidence: Source explicitly lists domains as part of the campaign infrastructure.
  hunt_leads:
    - lead: Search for high-frequency downloads of installers from the identified malicious domains.
      technique_id: T1204.002
      data_needed:
        - Proxy/Web logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Microsoft observed archive payloads being regenerated on every download request.
  mitigation_plan:
    - priority: immediate
      action: Enable Microsoft Defender tamper protection.
      owner: IT Operations
      addresses: Defense Evasion
      evidence: Microsoft recommends enabling tamper protection to block security weakening.
---

Microsoft Defender Experts is tracking an active malware campaign, identified as Silver Fox (Yinhu), which targets Chinese-speaking users and organizations with operations in China. The threat actors create fraudulent software download pages that mimic popular vendors, ranging from productivity tools like Sejda PDF to drivers like Razer Synapse. A critical feature of this campaign is server-side payload regeneration, where the attacker's infrastructure serves unique, hash-distinct installer archives for every request. This technique is specifically designed to bypass static signature-based detection. Once executed, the counterfeit installers drop malware that establishes persistence, attempts to disable host-based security protections, and communicates with attacker-controlled infrastructure. The campaign has impacted diverse sectors including healthcare, manufacturing, and government, necessitating a focus on network-level detection and robust endpoint hardening.

## Attack Chain

1. Initial Access: User navigates to a spoofed domain (e.g., pc-razerzone[.]com[.]cn) that clones a legitimate vendor's download page.
2. Delivery: User interacts with the "Download now" button, triggering a retrieval of a malicious archive from a secondary delivery host (e.g., gehie246[.]com).
3. Payload Generation: The delivery server performs per-request payload regeneration, serving a uniquely hashed archive to evade file-reputation services.
4. Execution: The user extracts and executes the malicious installer (e.g., app_setup.exe), initiating the infection chain.
5. Persistence: The installer executes secondary scripts to establish persistence mechanisms within the environment.
6. Defense Evasion: The malware attempts to weaken local security features, such as disabling security software or modifying tamper protection settings.
7. Command and Control: The compromised host beacons to attacker-controlled infrastructure to receive further instructions or facilitate data exfiltration.

## Impact

The campaign has resulted in confirmed system compromises across multiple organizations within the healthcare, manufacturing, gaming, technology, logistics, government, and higher education sectors. By impersonating trusted software, the actors gain unauthorized access to internal networks, potentially leading to long-term persistence and credential theft. The use of server-side regeneration makes traditional hash-based blocking ineffective, increasing the risk of successful delivery to end-user workstations.

## Recommendation

Prioritize network-level detection and endpoint hardening to mitigate this campaign.
- Implement DNS filtering to block navigation to the identified look-alike domains listed in the IOC table.
- Monitor network egress for connections to the identified delivery domains (e.g., gehie246[.]com) using proxy or firewall logs.
- Enable and enforce tamper protection and Microsoft Defender XDR features across all workstations to prevent the malware from disabling security controls.
- Deploy hunting queries for file-creation events where the process name matches common installer patterns (e.g., app_setup.*, zinst.*) followed by immediate, unexpected network connections.
- Educate users on the risks of downloading software from non-official sources, emphasizing the inspection of domain names for typosquatting (e.g., mindmoster[.]com[.]cn).
