---
brief_id: brief-2026-10-29-belden-icx35-bypass
event_id: brief-2026-10-29-belden-icx35-bypass
revision: 1
activity_at: "2026-10-29T15:33:07Z"
title: 'Belden ICX35: Security Policy Bypass Vulnerability'
slug: 2026-10-belden-icx35-bypass
description: A security policy bypass vulnerability in Belden ICX35 industrial gateways allows attackers to reset login lockouts, circumventing authentication security controls.
date: "2026-10-29T15:33:07Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
tags:
  - vulnerability
  - industrial-control-systems
  - authentication-bypass
vendors:
  - Belden
products:
  - ICX35-HWC-A (< 1.14.158)
  - ICX35-HWC-E (< 1.14.158)
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1407/
  - https://assets.belden.com/asset/3be80067-b211-423d-9be4-4e31bd43fbc9/PSIRT-9-Login-Lockout-Resets-in-ICX35.pdf
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - OT Security
  immediate_actions:
    - action: Inventory all deployed ICX35-HWC-A and ICX35-HWC-E devices
      owner: OT Security
      due: 48h
      evidence: Vulnerability affects ICX35-HWC-A and ICX35-HWC-E versions prior to 1.14.158
  hunt_leads:
    - lead: Monitor industrial gateway management interfaces for repeated failed login attempts that do not result in a lockout
      data_needed:
        - Gateway authentication and system audit logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows attacker to cause a bypass of the security policy via login lockout resets
  mitigation_plan:
    - priority: immediate
      action: Upgrade firmware to version 1.14.158 or later
      owner: IT Operations
      addresses: ICX35-HWC-A and ICX35-HWC-E firmware vulnerability
      evidence: Bulletin of security Belden PSIRT-9-Login-Lockout-Resets-in-ICX35
---

The French National Cybersecurity Agency (ANSSI) has published an advisory regarding a security vulnerability in Belden ICX35 industrial communication gateway products (models ICX35-HWC-A and ICX35-HWC-E). The vulnerability is identified in the vendor security bulletin "PSIRT-9-Login-Lockout-Resets-in-ICX35". It allows an unauthorized actor to bypass established security policies by resetting login lockout mechanisms. This could facilitate brute-force or credential-stuffing attacks against the device interface. No CVE identifier has been provided by the vendor at this time.

## Impact

The vulnerability results in a bypass of the security policy governing authentication attempts. This potentially allows an attacker to maintain persistent brute-force attempts against the device, as the lockout mechanism intended to mitigate such activity can be reset.

## Recommendation

- Identify all instances of Belden ICX35-HWC-A and ICX35-HWC-E gateways within the OT environment.
- Upgrade affected firmware to version 1.14.158 or later, as specified in the Belden PSIRT-9-Login-Lockout-Resets-in-ICX35 security bulletin.
- Monitor authentication logs on industrial gateway management interfaces for repeated login failures followed by successful access or anomalous resets of lockout counters.
