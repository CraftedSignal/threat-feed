---
title: Missing Brute-force Protection in Kingdom Communication Smart Video Intercom
slug: 2026-09-smart-intercom-brute-force
description: The Kingdom Communication Associated Smart Video Intercom System is vulnerable to credential-based attacks due to the absence of rate limiting or account lockout mechanisms on the authentication interface.
date: "2026-09-11T09:12:31Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:kingdomcommunication:smart_video_intercom_system:*:*:*:*:*:*:*:*
vendors:
  - Kingdom Communication Associated
products:
  - Smart Video Intercom System
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: Unauthenticated remote attackers can gain access to valid accounts through a large number of login attempts.
    confidence_band: high
cves:
  - id: CVE-2026-89174
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89174
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all Kingdom Communication Smart Video Intercom devices and move them behind a VPN or restricted firewall segment.
      owner: IT Operations
      due: 24h
      evidence: Source advisory confirms missing brute-force protection makes devices susceptible to unauthorized access via remote login attempts.
  mitigation_plan:
    - priority: immediate
      action: Configure network-level rate limiting on the gateway for the intercom management IP addresses.
      owner: SOC
      addresses: CVE-2026-89174
      evidence: Advisory states the device lacks internal brute-force protection, requiring external mitigation.
---

The Smart Video Intercom System, developed by Kingdom Communication Associated, contains a critical vulnerability related to missing brute-force protection. This flaw enables unauthenticated remote attackers to perform large-scale login attempts against the device's authentication endpoint. By leveraging the lack of account lockout or rate-limiting thresholds, an attacker can conduct automated credential stuffing or password spraying campaigns to brute-force valid user credentials. Successful exploitation allows unauthorized access to the intercom system, potentially granting attackers control over device functions or access to sensitive communication streams. This vulnerability represents a significant risk for organizations or residential environments deploying these intercoms in network-exposed configurations.

## Impact

The vulnerability carries a CVSS v3.1 base score of 7.5. Successful exploitation results in complete unauthorized account takeover. Impact includes potential exposure of video/audio feeds, unauthorized control over building entry/access management, and loss of device privacy. The scope of targeting is limited to installations of the Kingdom Communication Associated Smart Video Intercom System exposed to the public internet or accessible via the management network.

## Recommendation

Prioritize the identification of all internet-facing instances of the Kingdom Communication Smart Video Intercom System. Given the absence of native brute-force protection, implement network-level controls immediately.

- Restrict access to the intercom management interface to authorized IP ranges via firewall or VPN.
- Implement monitoring on network gateways for high volumes of HTTP 401 Unauthorized responses or repetitive authentication requests originating from single source IPs.
- Contact the vendor, Kingdom Communication Associated, for firmware updates that introduce mandatory account lockout or rate-limiting capabilities.
