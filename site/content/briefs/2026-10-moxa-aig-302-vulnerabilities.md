---
brief_id: brief-2026-10-16-moxa-aig-302-vulnerabilities
event_id: brief-2026-10-16-moxa-aig-302-vulnerabilities
revision: 2
activity_at: "2026-10-20T17:32:17Z"
revision_history:
  - revision: 2
    at: "2026-10-20T17:32:17Z"
    checksum: sha256:1ab4ec393e2b05927a7848844af2f392b79401f1013889c0272241466c22f8eb
    summary: new product
    changed_fields:
      - affected_products
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://www.cisa.gov/news-events/ics-advisories/icsa-26-293-03
title: Multiple Vulnerabilities in Moxa AIG-302 Industrial Computing Products
slug: 2026-10-moxa-aig-302-vulnerabilities
description: Moxa has disclosed two critical vulnerabilities, CVE-2026-109812 and CVE-2026-109813, affecting the AIG-302 industrial computing series firmware version 1.4.1 and earlier.
date: "2026-10-16T16:43:39Z"
lastmod: "2026-10-20T17:31:38Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Verified against source advisory.
cpes:
  - cpe:2.3:a:moxa:aig_302_series:*:*:*:*:*:*:*:*
tags:
  - industrial-control-systems
  - vulnerability
  - ot-security
vendors:
  - Moxa
products:
  - AIG-302 Series (<= 1.4.1)
  - AIG-302 ThingsPro Edge (<= 1.4.0)
cves:
  - id: CVE-2026-109812
    epss: 0.00125
    kev_status: "false"
  - id: CVE-2026-109813
    epss: 0.00153
    kev_status: "false"
references:
  - https://cyber.gc.ca/en/alerts-advisories/control-systems-moxa-security-advisory-av26-1055
  - https://www.moxa.com/en/support/product-support/security-advisory/mpsa-262560-cve-2026-109812,-cve-2026-109813-vulnerabilities-in-industrial-computing-products
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-293-03
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - OT Security
  immediate_actions:
    - action: Inventory all AIG-302 Series devices to determine vulnerable firmware status.
      owner: OT Security
      due: 48h
      evidence: Source alert for AV26-1055
  mitigation_plan:
    - priority: immediate
      action: Upgrade AIG-302 firmware to the version specified in MPSA-262560.
      owner: IT Operations
      addresses: CVE-2026-109812, CVE-2026-109813
      evidence: Vendor advisory MPSA-262560
updates:
  - at: "2026-10-20T17:31:38Z"
    level: L1
    summary: new product
    sources:
      - cisa
    source_urls:
      - https://www.cisa.gov/news-events/ics-advisories/icsa-26-293-03
---

Moxa has issued security advisory MPSA-262560 regarding vulnerabilities CVE-2026-109812 and CVE-2026-109813, which impact the AIG-302 series of industrial computers. These vulnerabilities affect all firmware versions up to and including v1.4.1. The vulnerabilities reside within the industrial computing platform, potentially exposing operational technology (OT) environments to unauthorized access or control if exploited. Given the nature of these industrial devices, successful exploitation could lead to system instability, unauthorized configuration changes, or the potential for lateral movement within a critical infrastructure network. Defenders should prioritize reviewing the vendor advisory and applying firmware updates to remediate these security gaps across their deployed industrial computing fleet.

## Impact

The AIG-302 series is utilized in industrial automation environments where system uptime and integrity are critical. If these vulnerabilities are successfully exploited, attackers could gain unauthorized influence over the device's functionality, leading to service disruption or potential compromise of the industrial control network. Organizations relying on these devices in manufacturing, energy, or utility sectors are at risk if patches are not applied according to the vendor's guidance.

## Recommendation

* Review the Moxa security advisory MPSA-262560 for specific mitigation details and patch availability.
* Audit OT environments for the presence of Moxa AIG-302 Series devices and verify firmware versions currently in operation.
* Update all instances of AIG-302 Series hardware to the latest firmware version released by Moxa to remediate CVE-2026-109812 and CVE-2026-109813.
* Implement network segmentation for industrial gateways to limit exposure to these devices from non-essential internal and external network segments.
