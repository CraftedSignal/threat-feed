---
brief_id: brief-2026-10-29-cisco-firewall-dos
event_id: brief-2026-10-29-cisco-firewall-dos
revision: 1
activity_at: "2026-10-29T10:03:00Z"
title: Cisco Secure Firewall ASA and FTD Vulnerability (CVE-2026-76418)
slug: 2026-10-cisco-firewall-dos
description: Cisco has released fixes for an actively exploited zero-day vulnerability (CVE-2026-76418) in the Remote Access SSL VPN service of its Secure Firewall ASA and FTD software.
date: "2026-10-29T10:03:00Z"
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
vendors:
  - Cisco
products:
  - Secure Firewall Adaptive Security Appliance (ASA)
  - Secure Firewall Threat Defense (FTD)
cves:
  - id: CVE-2026-76418
    cvss: 8.6
    kev_status: "false"
references:
  - https://www.securityweek.com/attackers-exploit-second-cisco-firewall-vpn-zero-day-since-august/
---

Cisco has issued patches for a vulnerability (CVE-2026-76418) affecting the Remote Access SSL VPN service in its Secure Firewall Adaptive Security Appliance (ASA) and Secure Firewall Threat Defense (FTD) software. The vulnerability, which has a CVSS score of 8.6, can be exploited by an unauthenticated, remote attacker to force the device. Cisco has confirmed the vulnerability is being actively exploited.
