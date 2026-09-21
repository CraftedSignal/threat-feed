---
title: Detecting Anomalous Cisco IOS XE Programmatic WebUI Configuration Changes
slug: 2026-09-cisco-ios-xe-webui-anomalies
description: Detection of programmatic configuration modifications on Cisco IOS XE devices via the WebUI WSMA process associated with the Salt Typhoon campaign.
date: "2026-09-21T19:10:49Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - Salt Typhoon
  - GhostEmperor
  - FamousSparrow
  - UNC5807
tags:
  - networking
  - infrastructure
  - salt-typhoon
vendors:
  - Cisco
products:
  - IOS XE
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The detection targets programmatic configuration changes to Cisco IOS XE devices via the WebUI WSMA process, indicative of potential exploitation.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The detection targets programmatic configuration changes to Cisco IOS XE devices via the WebUI WSMA process, indicative of potential persistence mechanism installation.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a
  - https://blog.talosintelligence.com/salt-typhoon-analysis/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Network Security
  immediate_actions:
    - action: Enable and ingest Cisco IOS XE syslog events into your SIEM
      owner: Network Security
      due: 48h
      evidence: Source requirement for detection implementation
  mitigation_plan:
    - priority: immediate
      action: Review all administrative access to WebUI and restrict or disable if not required
      owner: Network Security
      addresses: T1190
      evidence: Standard security practice for network edge device hardening
---

This brief addresses the risk of unauthorized programmatic configuration changes to Cisco IOS XE networking devices. These changes, specifically targeting the WebUI WSMA process, have been observed in activity attributed to the Salt Typhoon campaign. The WebUI component of Cisco IOS XE has previously been targeted by threat actors to gain persistent access, exfiltrate configurations, or pivot into internal networks. Monitoring for programmatic configuration changes initiated through the WSMA (Web Services Management Agent) process provides a critical visibility point for detecting exploitation attempts or unauthorized administrative actions. Defensive teams should monitor syslog data for specific mnemonic markers that indicate configuration modifications via the web interface.

## Attack Chain

1. Attacker identifies an internet-facing or reachable Cisco IOS XE device with the WebUI enabled.
2. Attacker performs initial access or privilege escalation (T1190, T1078) to gain authenticated access to the WebUI.
3. Attacker triggers the WSMA process via the WebUI to inject commands or alter device configuration.
4. The device generates a syslog entry with facility SYS and mnemonic CONFIG_P.
5. The message text explicitly logs the source as "Configured programmatically by process SEP_webui_wsma_http".
6. Attacker leverages the modified configuration to establish persistence or facilitate further network intrusion.
7. Final objective is achieved, such as credential harvesting, traffic redirection, or lateral movement within the network infrastructure.

## Impact

Successful exploitation of Cisco IOS XE devices allows attackers to establish persistent, stealthy access within a target's network infrastructure. This can lead to the compromise of sensitive traffic, unauthorized access to internal systems, and the ability to exfiltrate enterprise or government data. The Salt Typhoon campaign emphasizes the targeting of critical infrastructure and network edge devices to facilitate long-term surveillance.

## Recommendation

Prioritize the ingestion of Cisco IOS XE syslog data into your SIEM and enable logging for WebUI activity to detect anomalous programmatic configuration changes. Configure alerts specifically on the CONFIG_P mnemonic and the SEP_webui_wsma_http process to identify potential Salt Typhoon activity. Use the risk-based alerting framework to aggregate and correlate these events with other suspicious network behavior observed on the affected destination devices.
