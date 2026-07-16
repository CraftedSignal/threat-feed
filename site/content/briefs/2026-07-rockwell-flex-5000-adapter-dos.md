---
title: Rockwell Automation Flex 5000 Adapter Vulnerability Leads to Denial of Service
slug: 2026-07-rockwell-flex-5000-adapter-dos
description: A denial-of-service vulnerability (CVE-2026-12659), categorized as a Double Free issue (CWE-415), exists in Rockwell Automation Flex 5000 Adapter version 6.011 due to improper handling of crafted CIP packets, which could allow an unauthenticated attacker to cause a denial-of-service condition requiring a power cycle to recover.
date: "2026-07-16T16:09:56Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ics
  - ot
  - critical-manufacturing
  - information-technology
  - denial-of-service
  - vulnerability
vendors:
  - Rockwell Automation
products:
  - Flex 5000 Adapter (6.011)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Successful exploitation of this vulnerability could allow an attacker to cause a denial-of-service condition on the affected product.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A power cycle is required to recover the module and associated I/O.
    confidence_band: high
cves:
  - id: CVE-2026-12659
    epss: 0.00253
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-197-08
  - https://www.cve.org/CVERecord?id=CVE-2026-12659
  - https://support.rockwellautomation.com/app/answers/answer_view/a_id/1085012/loc/en_US#__highlight
  - https://www.rockwellautomation.com/en-us/trust-center/security-advisories/advisory.SD1789.html
---

CISA has released an advisory regarding a denial-of-service (DoS) vulnerability, identified as CVE-2026-12659, affecting Rockwell Automation Flex 5000 Adapter version 6.011. This flaw stems from a Double Free issue (CWE-415) due to the improper handling of exceptional conditions when the adapter processes specially crafted Common Industrial Protocol (CIP) packets. An unauthenticated attacker could exploit this vulnerability by sending malformed CIP packets to the device, leading to a DoS condition. The affected Flex 5000 Adapter module and its associated I/O would then require a power cycle to recover, causing operational disruption in critical infrastructure sectors such as Critical Manufacturing and Information Technology globally. While there is no known public exploitation targeting this vulnerability reported to CISA at this time, the potential for disruption necessitates immediate attention from defenders.

## Attack Chain

1. **Crafted Packet Generation**: An attacker crafts a malicious Common Industrial Protocol (CIP) packet designed to trigger a Double Free condition within the Rockwell Automation Flex 5000 Adapter version 6.011.
2. **Network Transmission**: The attacker sends the crafted CIP packet over the network to the vulnerable Flex 5000 Adapter.
3. **Packet Processing**: The Flex 5000 Adapter receives and attempts to process the malformed CIP packet.
4. **Vulnerability Trigger**: Due to improper handling of exceptional conditions related to memory management (Double Free, CWE-415), the crafted packet causes an unrecoverable error within the device's firmware.
5. **Denial-of-Service**: The adapter ceases to function, entering a denial-of-service state and halting associated I/O operations.
6. **Operational Disruption**: The affected industrial control system experiences operational disruption until the adapter is manually power cycled to restore functionality.

## Impact

Successful exploitation of CVE-2026-12659 would result in a denial-of-service condition on the affected Rockwell Automation Flex 5000 Adapter. This would lead to operational disruption, as the module and its associated I/O would become unresponsive. Recovery necessitates a manual power cycle, causing downtime that can significantly impact critical processes. The vulnerability affects devices deployed worldwide, particularly within the Critical Manufacturing and Information Technology sectors. The CVSS v3.1 base score for this vulnerability is 7.5 (High), reflecting the significant availability impact without requiring user interaction or privileges.

## Recommendation

* **Upgrade immediately**: Upgrade Rockwell Automation Flex 5000 Adapter devices from version 6.011 to version 6.012 to address CVE-2026-12659.
* **Implement Network Segmentation**: Ensure that control system networks, where Flex 5000 Adapters are deployed, are isolated from business networks and segment them behind firewalls to restrict unauthorized access to devices susceptible to CVE-2026-12659.
* **Restrict Internet Exposure**: Minimize network exposure for all control system devices, including Flex 5000 Adapters, by ensuring they are not directly accessible from the internet.
* **Utilize Secure Remote Access**: When remote access is necessary for ICS devices, use secure methods such as Virtual Private Networks (VPNs) and ensure VPNs are updated to the most current version available.
