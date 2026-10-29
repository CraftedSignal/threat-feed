---
brief_id: brief-2026-10-29-hitachi-tro600
event_id: brief-2026-10-29-hitachi-tro600
revision: 1
activity_at: "2026-10-29T23:07:35Z"
title: Hitachi Energy TRO600 Series Vulnerabilities (CVE-2026-10756, CVE-2026-106087)
slug: 2026-10-hitachi-tro600
description: Hitachi Energy TRO600 series products are vulnerable to unauthorized service access via network restriction bypass and unauthenticated arbitrary file read, potentially leading to credential exposure.
date: "2026-10-29T23:07:35Z"
type: threat
types:
  - threat
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:hitachienergy:tro600:*:*:*:*:*:*:*:*
tags:
  - industrial-control-systems
  - energy
  - ics-advisory
vendors:
  - Hitachi Energy
products:
  - TRO600 (<= 9.2.1.6)
  - TRO600 (<= 9.1.1.0)
cves:
  - id: CVE-2026-106087
    epss: 0.00247
    kev_status: "false"
  - id: CVE-2026-10756
    epss: 0.0018
    kev_status: "false"
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-302-02
  - https://www.cve.org/CVERecord?id=CVE-2026-10756
  - https://www.cve.org/CVERecord?id=CVE-2026-106087
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all vulnerable TRO600 devices to version 9.2.2.1 or 9.1.2.0.
      owner: IT Operations
      due: 72h
      evidence: Vendor fix recommendation in ICSA-26-302-02.
  hunt_leads:
    - lead: Monitor for unauthorized file access requests to configuration or credential paths on TRO600 devices.
      technique_id: T1005
      data_needed:
        - Device web server logs
        - System access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: CVE-2026-106087 allows an unauthenticated attacker to read arbitrary files.
  mitigation_plan:
    - priority: immediate
      action: Isolate TRO600 devices from the public internet and business networks.
      owner: IT Operations
      addresses: CVE-2026-10756, CVE-2026-106087
      evidence: CISA general mitigation factors for ICS.
---

Hitachi Energy TRO600 series products contain two high-severity vulnerabilities. CVE-2026-10756 allows an authenticated attacker to bypass network restrictions and access services intended to be reachable only from localhost via port forwarding. CVE-2026-106087 allows an unauthenticated attacker to perform arbitrary file reads, potentially exposing sensitive configuration files and credentials. No evidence of in-the-wild exploitation was provided in the advisory.

## Impact
Successful exploitation may result in unauthorized access to sensitive functionality, disclosure of confidential information including password data, and availability impact on Industrial Control System (ICS) environments.

## Recommendation
- Update TRO600 series devices to version 9.2.2.1 or 9.1.2.0 as applicable to remediate identified vulnerabilities.
- Minimize network exposure for all control system devices by ensuring they are not directly accessible from the internet.
- Isolate control system networks behind firewalls and utilize VPNs for remote access, ensuring VPN infrastructure is kept current.
- Implement defense-in-depth strategies as outlined in CISA's ICS cybersecurity best practices.
