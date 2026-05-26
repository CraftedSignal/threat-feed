---
title: Cryptojacking Campaign Abusing ScreenConnect and SEO Poisoning
slug: 2026-05-cryptojacking-screenconnect
description: An active cryptojacking campaign uses SEO poisoning, AI chatbot interactions, and ScreenConnect abuse to target high-performance PCs, aiming to maximize GPU mining yield and establish persistent remote access for potential data theft or ransomware attacks.
date: "2026-05-26T22:09:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cryptojacking
  - seo-poisoning
  - screenconnect
  - dll-sideloading
vendors:
  - Microsoft
  - ConnectWise
  - Dynu
products:
  - ScreenConnect
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://www.microsoft.com/en-us/security/blog/2026/05/26/poisoned-search-results-gpu-mining-cryptojacking-campaign-abusing-screenconnect-microsoft-net-utilities/
iocs:
  - type: domain
    value: gleeze.com
ioc_counts:
  domain: 1
rules:
  - title: Detect ScreenConnect Client Connection to Known C2
    description: Detects ScreenConnect client attempting to connect to a known malicious server.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Silent Installation of ScreenConnect via msiexec
    description: Detects msiexec installing DLLs masquerading as Visual C++ Redistributable, indicative of ScreenConnect installation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Microsoft Defender Experts identified an active cryptojacking campaign targeting users likely to own high-performance GPUs. This campaign leverages SEO poisoning and, more recently, AI chatbot interactions to deliver malicious software. Attackers impersonate trusted system utilities like CrystalDiskInfo, HWMonitor, and others to lure users into downloading malware. Instead of maximizing infection volume, the threat actor focuses on compromising systems with higher mining value. The campaign establishes persistent remote access through abused ScreenConnect deployments, potentially leading to data theft, lateral movement, or ransomware activity. Since March 2026, over 150 malicious domains have been identified serving these malicious tools.

## Attack Chain

1. Users search for common system utilities or hardware-monitoring software (e.g., CrystalDiskInfo, HWMonitor) on search engines or request software recommendations from AI chatbots.
2. Manipulated search results or chatbot responses direct users to attacker-controlled lookalike sites.
3. The user clicks a download button on the fake site, which retrieves a ZIP archive hosted on a campaign-specific subdomain of gleeze.com.
4. The ZIP archive contains a legitimate executable for the spoofed utility and a malicious DLL named autorun.dll.
5. When the user launches the executable, the legitimate program loads autorun.dll from the same folder via DLL sideloading.
6. The malicious autorun.dll uses msiexec.exe to silently install a second malicious DLL named vcredist_x64.dll, which is a packaged installer for ScreenConnect.
7. The ScreenConnect client is installed and attempts to communicate with the attacker-controlled server at 193.42.11[.]108.
8. The attacker gains persistent remote access to the compromised system, enabling cryptocurrency mining and potential further malicious activities.

## Impact

This campaign targets users with high-performance GPUs to maximize cryptocurrency mining yield. Successful compromise leads to unauthorized resource consumption and potential financial losses for the victim. The established persistent remote access through ScreenConnect could also enable data theft, lateral movement within the network, or ransomware deployment, resulting in significant damage and disruption.

## Recommendation

*   Enable cloud-delivered protection and run EDR in block mode in Microsoft Defender to detect and block activity associated with this campaign.
*   Enable attack surface reduction rules in Microsoft Defender to reduce the risk of DLL sideloading, as described in the attack chain.
*   Block the domain `gleeze.com` and IP address `193.42.11[.]108` at the network perimeter, as mentioned in the IOC table.
*   Monitor process creation events for `msiexec.exe` installing DLLs masquerading as Visual C++ Redistributable (vcredist_x64.dll), and deploy the related Sigma rule to detect suspicious installations.
