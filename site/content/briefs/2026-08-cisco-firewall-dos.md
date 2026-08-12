---
title: Active Exploitation of CVE-2026-20349 in Cisco Secure Firewall
slug: 2026-08-cisco-firewall-dos
description: Cisco Secure Firewall ASA and FTD devices are subject to active exploitation of a zero-day vulnerability, CVE-2026-20349, which allows remote, unauthenticated attackers to cause a denial-of-service condition via crafted HTTP requests.
date: "2026-08-12T05:58:38Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
vendors:
  - Cisco
products:
  - Secure Firewall Adaptive Security Appliance
  - Secure Firewall Threat Defense
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: A remote, unauthenticated attacker can cause an appliance to reload and enter a denial-of-service (DoS) condition by sending a specially crafted HTTP request to the Remote Access SSL VPN service.
    confidence_band: high
cves:
  - id: CVE-2026-20349
    cvss: 8.6
references:
  - https://www.securityweek.com/cisco-patches-firewall-zero-day-exploited-for-dos-attacks/
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch CVE-2026-20349 on all internet-facing Cisco Secure Firewall devices
      owner: IT Operations
      due: 24h
      evidence: Cisco advisory and CISA KEV mandate
  mitigation_plan:
    - priority: immediate
      action: Verify current version of ASA/FTD software
      owner: IT Operations
      addresses: CVE-2026-20349
      evidence: Vendor patch recommendation
---

Cisco has released patches for a zero-day vulnerability, identified as CVE-2026-20349, affecting its Secure Firewall Adaptive Security Appliance (ASA) and Secure Firewall Threat Defense (FTD) software. The vulnerability resides in the Remote Access SSL VPN service of the affected devices and stems from improper handling of HTTP requests. Cisco confirmed that the vulnerability is being actively exploited in the wild as of August 2026, leading to a denial-of-service (DoS) condition where the appliance reloads unexpectedly. Given that these devices act as critical security infrastructure, successful exploitation can result in the loss of perimeter security and visibility, potentially facilitating further malicious activities. CISA has added this vulnerability to its Known Exploited Vulnerabilities (KEV) catalog, mandating remediation for federal agencies by August 14, 2026.

## Impact

Successful exploitation of CVE-2026-20349 results in an immediate DoS condition for the targeted firewall, causing it to reload. This disruption impacts network availability and bypasses security controls that are reliant on the appliance for inspection and filtering. Organizations across all sectors utilizing these Cisco appliances for VPN termination are at risk of service outages and increased exposure to secondary attacks while the firewall is offline.

## Recommendation

- Apply the vendor-supplied hotfixes immediately to all affected Cisco Secure Firewall ASA and FTD devices.
- Review Cisco security advisory documentation for specific version upgrade requirements.
- Prioritize patching in compliance with the CISA Known Exploited Vulnerabilities (KEV) mandate.
- Monitor firewall logs for unusual spikes in HTTP traffic directed toward the SSL VPN endpoints.
