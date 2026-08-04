---
title: Multiple Denial of Service Vulnerabilities in PJSIP pjmedia
slug: 2026-08-pjsip-dos
description: Multiple vulnerabilities in the PJSIP pjmedia library can be exploited by a remote, unauthenticated attacker to trigger a denial of service condition, potentially disrupting telecommunications services.
date: "2026-08-04T13:37:27Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - voip
  - infrastructure
vendors:
  - PJSIP
products:
  - pjmedia
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Ein entfernter, anonymer Angreifer kann mehrere Schwachstellen in PJSIP ausnutzen, um einen Denial of Service Angriff durchzuführen.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2642
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Network Security
  immediate_actions:
    - action: Inventory internal VoIP and PBX software to identify usage of PJSIP/pjmedia
      owner: IT Operations
      due: 48h
      evidence: Advisory identifies vulnerabilities within the PJSIP pjmedia library
  mitigation_plan:
    - priority: medium_term
      action: Patch VoIP/PBX software once security updates are released by vendors
      owner: IT Operations
      addresses: pjmedia vulnerabilities
      evidence: Software vendors must release updates to address identified library vulnerabilities
---

The BSI has released an advisory regarding multiple vulnerabilities identified within the PJSIP pjmedia library. These security flaws allow a remote, unauthenticated attacker to initiate Denial of Service (DoS) conditions against services that utilize the affected media processing stack. PJSIP is a widely deployed open-source multimedia communication library used in numerous Voice over IP (VoIP) applications, softphones, and telecommunication infrastructure components. By sending specially crafted network traffic, an attacker can trigger crashes or resource exhaustion within the affected applications. Given the ubiquitous nature of PJSIP in real-time communication systems, organizations relying on softswitches, IP-PBX systems, or custom VoIP applications should review their software dependencies for the affected components and monitor for unexpected service interruptions.

## Impact

Successful exploitation of these vulnerabilities leads to a denial of service state, causing affected telecommunications applications or services to crash or become unresponsive. This impact directly threatens the availability of real-time communication services, potentially affecting internal and external telephony operations, contact center availability, and emergency communication pathways. The scope of impact is dependent on the specific deployment architecture of the VoIP infrastructure using the vulnerable pjmedia library version.

## Recommendation

* Monitor system logs for repeated application crashes or service restarts for any VoIP or communication applications utilizing PJSIP.
* Identify if any internal telephony or communication platforms incorporate the PJSIP pjmedia library.
* Contact upstream software vendors for internal VoIP and PBX solutions to determine if their products include the vulnerable version of PJSIP and when a security patch will be provided.
* Limit exposure of VoIP signaling and media ports to trusted networks or authorized IP ranges to mitigate the risk of remote exploitation by unauthenticated actors.
