---
brief_id: brief-2026-10-29-cisco-firewall-dos
event_id: brief-2026-10-29-cisco-firewall-dos
revision: 2
activity_at: "2026-10-29T11:37:05Z"
revision_history:
  - revision: 2
    at: "2026-10-29T11:37:05Z"
    checksum: sha256:9d144088a4b28afc0365dbfdbcea771490065a2e0c6a0eb390f36961fa88e512
    summary: added coverage for Secure Firewall Adaptive Security Appliance (ASA) Software +1 products
    changed_fields:
      - action_plan
      - affected_products
      - content
      - lastmod
      - priority_signals
      - references
      - summary
      - tags
      - title
      - ttps
      - updates
    source_urls:
      - https://thehackernews.com/2026/10/cisco-patches-actively-exploited-asa.html
title: 'Cisco Secure Firewall ASA and FTD: Denial of Service via SSL VPN (CVE-2026-76418)'
slug: 2026-10-cisco-firewall-dos
description: Cisco patched an actively exploited logic vulnerability (CVE-2026-76418) in the SSL VPN service of ASA and FTD software that allows unauthenticated attackers to trigger a device reload and denial-of-service condition.
date: "2026-10-29T10:03:00Z"
lastmod: "2026-10-29T11:36:24Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.securityweek.com/attackers-exploit-second-cisco-firewall-vpn-zero-day-since-august/
  observed_at: "2026-10-29T00:00:00Z"
  confidence: high
source_assessment:
  reliability: C
  credibility: "2"
  rating: C2
  likelihood: likely
tags:
  - cve-2026-76418
  - denial-of-service
  - cisco
  - vpn
vendors:
  - Cisco
products:
  - Secure Firewall Adaptive Security Appliance (ASA)
  - Secure Firewall Threat Defense (FTD)
  - Secure Firewall Adaptive Security Appliance (ASA) Software
  - Secure Firewall Threat Defense (FTD) Software (< 7.0.11, 7.2.13, 7.4.9, 7.6.7, 7.7.14, 10.0.3, 10.1.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Successful exploit could allow the attacker to cause the affected device to reload, resulting in a DoS condition.
    confidence_band: high
cves:
  - id: CVE-2026-76418
    cvss: 8.6
    kev_status: "false"
references:
  - https://www.securityweek.com/attackers-exploit-second-cisco-firewall-vpn-zero-day-since-august/
  - https://thehackernews.com/2026/10/cisco-patches-actively-exploited-asa.html
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch ASA/FTD software to versions containing the fix for CVE-2026-76418
      owner: IT Operations
      due: 24h
      evidence: Cisco advisory confirming active exploitation
  hunt_leads:
    - lead: Identify devices with SSL VPN enabled and secondary authentication configured in tunnel groups
      technique_id: T1190
      data_needed:
        - Device running configuration (show running-config)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Cisco states vulnerability occurs when secondary-authentication-server-group is configured in tunnel group scope
  mitigation_plan:
    - priority: immediate
      action: Disable secondary authentication on tunnel groups or DefaultWEBVPNGroup if currently exposed
      owner: IT Operations
      addresses: CVE-2026-76418
      evidence: Cisco recommended workaround
updates:
  - at: "2026-10-29T11:36:24Z"
    level: L1
    summary: added coverage for Secure Firewall Adaptive Security Appliance (ASA) Software +1 products
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/10/cisco-patches-actively-exploited-asa.html
---

Cisco has released security patches for a high-severity vulnerability (CVE-2026-76418) affecting the Remote Access SSL VPN service in Cisco Secure Firewall ASA and FTD software. The flaw, which stems from logic errors when secondary authentication is configured on a tunnel group, can be exploited by an unauthenticated, remote attacker sending a crafted request. Successful exploitation causes the affected device to reload unexpectedly, resulting in a denial-of-service (DoS) condition. Cisco confirmed active exploitation of this vulnerability as of October 2026.

## Impact
Successful exploitation allows unauthenticated remote attackers to trigger an unexpected device reload, resulting in a complete denial-of-service for the affected network appliance.

## Recommendation
- Immediately apply the available software patches for your version of Cisco Secure Firewall ASA or FTD.
- If immediate patching is not feasible, implement the recommended workarounds: disable the tunnel group list if 'DefaultWEBVPNGroup' does not use secondary authentication, or disable secondary authentication on any user-configured or default tunnel groups ('DefaultWEBVPNGroup').
- Review the deployed remote access VPN policy and current device configuration via Cisco Secure FMC or FDM to identify active secondary authentication configurations.
