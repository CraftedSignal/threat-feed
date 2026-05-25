---
title: CISA ICS Security Advisories Address Vulnerabilities in Multiple Vendor Products
slug: 2026-05-cisa-ics-advisories
description: CISA published ICS advisories addressing vulnerabilities in products from ABB, Hitachi Energy, Kieback & Peter, ScadaBR, Siemens, and ZKTeco, recommending mitigations and updates.
date: "2026-05-25T14:23:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ics
  - scada
  - vulnerability
vendors:
  - ABB
  - Hitachi Energy
  - Kieback & Peter
  - ScadaBR
  - Siemens
  - ZKTeco
products:
  - B&R Automation Runtime (< 6.4)
  - B&R Automation Studio (< 6.5)
  - B&R PCs
  - CoreSense HM (<= 2.3.1)
  - CoreSense M10 (<= 1.4.1.12)
  - Terra AC Wallbox (JP) (<= 1.8.33)
  - GMS600 (1.3.0 to 1.3.1)
  - DDC Building Controllers
  - ScadaBR (1.2.0)
  - RUGGEDCOM APE1808
  - CCTV Cameras (< V5.0.1.2.20260421)
references:
  - https://www.cisa.gov/news-events/cybersecurity-advisories
  - https://cyber.gc.ca/en/alerts-advisories/control-systems-cisa-ics-security-advisories-av26-506
rules:
  - title: Detect Outdated ZKTeco CCTV Camera Firmware
    description: Detects network requests originating from ZKTeco CCTV cameras with firmware versions prior to V5.0.1.2.20260421.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595.002
    data_sources:
      - network_connection
      - windows
  - title: Detect ABB Automation Studio Process Creation
    description: Detects execution of ABB Automation Studio-related processes.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On May 25, 2026, CISA published multiple ICS security advisories addressing vulnerabilities across a range of industrial control systems and related products. The advisories, released between May 18 and May 24, 2026, cover products from vendors including ABB, Hitachi Energy, Kieback & Peter, ScadaBR, Siemens, and ZKTeco. These vulnerabilities span a variety of product types, including automation runtimes, building controllers, and CCTV cameras. Successful exploitation of these vulnerabilities could allow attackers to disrupt industrial processes, compromise building automation systems, or gain unauthorized access to surveillance systems. Defenders should review the specific advisories and apply the recommended mitigations and updates to protect their environments.

## Attack Chain

Given the variety of products and vulnerabilities, a generalized attack chain is described below. Specific steps will vary depending on the targeted product and vulnerability.

1.  **Initial Access:** An attacker identifies a vulnerable ICS product exposed to a network, either directly or through a connected system.
2.  **Vulnerability Exploitation:** The attacker crafts a specific exploit tailored to the identified vulnerability (e.g., remote code execution in ABB B&R Automation Runtime or Siemens RUGGEDCOM APE1808).
3.  **Privilege Escalation:** Once initial access is gained, the attacker attempts to escalate privileges within the system to gain broader control.
4.  **Lateral Movement:** The attacker leverages their elevated privileges to move laterally within the OT network, targeting other critical systems.
5.  **System Compromise:** The attacker compromises targeted systems, potentially including HMIs, engineering workstations, or other control devices.
6.  **Impact:** The attacker manipulates ICS processes, leading to disruption of operations, equipment damage, or data theft. For example, a compromised ZKTeco CCTV camera system could be used for surveillance or denial of service.
7. **Persistence:** The attacker establishes persistent access to the compromised ICS environment.

## Impact

The successful exploitation of vulnerabilities in these ICS products could have significant consequences, including disruption of industrial processes, compromise of building automation systems, and unauthorized access to surveillance systems. Depending on the specific vulnerability and targeted system, the impact could range from localized equipment damage to widespread operational outages and data breaches. Sectors that rely heavily on ICS, such as manufacturing, energy, and transportation, are particularly at risk.

## Recommendation

*   Review the CISA ICS Advisories linked in the references and prioritize patching ABB B&R Automation Runtime (versions prior to 6.4) and ABB B&R Automation Studio (versions prior to 6.5).
*   Apply the necessary updates provided by the respective vendors (ABB, Hitachi Energy, Kieback & Peter, ScadaBR, Siemens, and ZKTeco) for the affected products.
*   Monitor network traffic for unusual activity related to the affected products, such as unauthorized access attempts or unexpected data transfers.
*   Implement network segmentation to limit the potential impact of a successful compromise, following industry best practices for ICS security.
