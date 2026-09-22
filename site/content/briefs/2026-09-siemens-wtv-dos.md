---
title: Denial of Service Vulnerability in Siemens WTV676 and WTV776
slug: 2026-09-siemens-wtv-dos
description: An unauthenticated remote attacker can exploit an improper input validation vulnerability (CVE-2026-89207) in Siemens WTV676 and WTV776 devices to force them into protection mode, resulting in a permanent loss of remote web access.
date: "2026-09-22T16:46:59Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - industrial-control-systems
  - denial-of-service
  - energy
vendors:
  - Siemens
products:
  - WTV676 (all versions < 3.94)
  - WTV776 (all versions < 4.17)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: This could allow an unauthenticated remote attacker to force the device into protection mode, which results in losing remote connectivity functions (Web Access).
    confidence_band: high
cves:
  - id: CVE-2026-89207
    cvss: 6.5
    epss: 0.00336
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-265-08
  - https://cert-portal.siemens.com/productcert/html/ssa-823812.html
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - OT Security
  immediate_actions:
    - action: Upgrade WTV676 devices to v3.94 and WTV776 devices to v4.17
      owner: IT Operations
      due: 72h
      evidence: Vendor remediation guidance for CVE-2026-89207
  mitigation_plan:
    - priority: immediate
      action: Isolate affected devices from the internet using firewalls
      owner: OT Security
      addresses: CVE-2026-89207
      evidence: CISA recommended practices for ICS devices
---

Siemens WTV676 and WTV776 industrial communication devices are affected by a medium-severity vulnerability (CVE-2026-89207) stemming from improper validation of input received from backend services. An unauthenticated remote attacker can exploit this flaw to force the affected hardware into a protection mode. Once in this state, the devices disable their Web Access functionality, effectively resulting in a denial-of-service condition for remote management and connectivity. This vulnerability impacts devices deployed globally within the energy sector. Siemens has released patched firmware versions, and organizations are advised to update affected hardware and restrict network exposure for these devices.

## Impact

Successful exploitation results in a denial-of-service condition where remote administrative access via the Web Interface is disabled. This loss of connectivity may disrupt operational monitoring and management of systems within energy sector environments. The vulnerability is considered reachable by an unauthenticated attacker over the network.

## Recommendation

- Upgrade WTV676 devices to firmware version 3.94 or later to address CVE-2026-89207.
- Upgrade WTV776 devices to firmware version 4.17 or later to address CVE-2026-89207.
- Implement network segmentation to isolate control system networks from the public internet and business networks.
- Enforce strict access control lists (ACLs) to ensure that only authorized hosts can communicate with the device web interfaces.
