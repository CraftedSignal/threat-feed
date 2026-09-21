---
title: Unauthorized Access Vulnerability in DesktopSMS
slug: 2026-09-desktopsms-unauthorized-access
description: DesktopSMS version 1.11.0 contains a local service vulnerability allowing an unauthenticated attacker to bypass pairing and perform unauthorized SMS operations via loopback communication.
date: "2026-09-21T22:30:51Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:mrpear:desktopsms:1.11.0:*:*:*:*:*:*:*
vendors:
  - MrPear
products:
  - DesktopSMS (1.11.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: Attackers can exploit the unauthenticated local service through same-device loopback to perform privileged SMS operations using the victim application's permissions.
    confidence_band: high
cves:
  - id: CVE-2026-94540
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94540
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory systems for DesktopSMS 1.11.0
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-94540 affects DesktopSMS 1.11.0
  mitigation_plan:
    - priority: immediate
      action: Remove or disable DesktopSMS 1.11.0
      owner: IT Operations
      addresses: CVE-2026-94540
      evidence: Product contains unauthorized access vulnerability
---

DesktopSMS version 1.11.0, developed by MrPear, is susceptible to an unauthorized access vulnerability within its local service component. The flaw enables a local attacker to interact with the application's service without requiring valid pairing confirmation or user interaction. By leveraging the same-device loopback interface, an attacker can bypass existing authentication controls to transmit SMS messages, exfiltrate SMS-derived content, and persist an attacker-selected paired identity. This allows the attacker to conduct privileged SMS operations using the security context and permissions of the DesktopSMS application. Because this requires local access to the device to interface with the loopback service, it is a significant concern for multi-user environments or systems where local access by untrusted actors is a threat.

## Impact

Successful exploitation allows a local attacker to hijack the SMS capabilities of the DesktopSMS application. Impact includes unauthorized message transmission, interception of sensitive SMS-based content (such as two-factor authentication codes), and long-term persistence of a rogue identity within the application's pairing configuration. This can lead to account takeover or information disclosure for services protected by SMS verification.

## Recommendation

1. Review all endpoints for the presence of DesktopSMS version 1.11.0.
2. If the application is not business-critical, uninstall it from all workstations to remove the attack surface.
3. Restrict local user permissions on systems where DesktopSMS is required to prevent unauthorized process interaction.
4. Monitor for updates from MrPear and apply patches immediately upon release to address CVE-2026-94540.
