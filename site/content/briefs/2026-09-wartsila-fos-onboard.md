---
title: Hard-coded Cryptographic Keys in Wärtsilä FOS-Onboard
slug: 2026-09-wartsila-fos-onboard
description: Wärtsilä FOS-Onboard version 5.07.0923.01 contains hard-coded cryptographic keys in the Update Controller and robot testing framework that could facilitate unauthorized code execution, update deployment, and credential theft.
date: "2026-09-15T16:31:51Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - ics
  - transportation
  - patch-management
  - cve-2026-78225
  - cve-2026-81855
vendors:
  - Wärtsilä
products:
  - FOS-Onboard (5.07.0923.01)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Successful exploitation of these vulnerabilities could allow an attacker to deliver an unauthorized update, execute code, or extract credentials to allow the attacker to impersonate a privileged client.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1552.001
    technique_name: Credentials in Files
    evidence: Successful exploitation of these vulnerabilities could allow an attacker to ... extract credentials to allow the attacker to impersonate a privileged client.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-258-02
  - https://www.cve.org/CVERecord?id=CVE-2026-78225
  - https://www.cve.org/CVERecord?id=CVE-2026-81855
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - OT Security
  immediate_actions:
    - action: Contact Wärtsilä to obtain the security patch for FOS-Onboard 5.07.0923.01.
      owner: OT Security
      due: 24h
      evidence: Mitigation section of the advisory.
  mitigation_plan:
    - priority: immediate
      action: Isolate FOS-Onboard network segments from internet and business office networks.
      owner: IT Operations
      addresses: CVE-2026-78225, CVE-2026-81855
      evidence: Recommended practices section of the advisory.
---

Wärtsilä has disclosed two critical vulnerabilities in the FOS-Onboard software, version 5.07.0923.01, related to the use of hard-coded cryptographic keys. The first vulnerability, CVE-2026-78225, affects the deployer-ng Update Controller component, while the second, CVE-2026-81855, impacts the robot testing framework. These flaws present a significant risk to maritime transportation systems, as they allow unauthenticated remote attackers to bypass security controls. By leveraging these hard-coded keys, an attacker could potentially sign and deliver malicious software updates, execute arbitrary code, or extract sensitive credentials required to impersonate privileged clients. The vulnerabilities were reported to CISA by Cydome Security Ltd. Given the nature of these assets in global transportation, rapid patching or implementation of strict network isolation is essential to prevent exploitation in critical infrastructure environments.

## Impact

Successful exploitation could result in full system compromise, unauthorized persistent access, and the ability to manipulate maritime navigation or fleet management operations. These vulnerabilities impact the transportation sector globally. If exploited, an attacker could gain the ability to push malicious firmware or software updates to onboard systems, leading to severe operational disruption or safety risks. No known public exploitation has been reported as of September 2026.

## Recommendation

* Contact Wärtsilä directly to obtain and deploy the security patch for FOS-Onboard version 5.07.0923.01.
* Isolate FOS-Onboard systems from the internet and business networks by placing them behind robust firewalls.
* If remote access to the system is required, enforce the use of secure VPNs, ensuring that the VPN infrastructure itself is patched and hardened.
* Conduct a risk assessment to determine the exposure of FOS-Onboard assets to unauthorized network segments.
