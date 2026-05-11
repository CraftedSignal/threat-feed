---
title: CISA ICS Advisories Address Vulnerabilities in Multiple Products
slug: 2026-05-cisa-ics-advisories
description: CISA published ICS advisories addressing vulnerabilities in ABB B&R Automation Runtime and Studio, ABB B&R PVI, Hitachi Energy PCM600, Johnson Controls CEM AC2000, and MAXHUB Pivot Client Application, advising users to apply necessary updates and mitigations.
date: "2026-05-11T15:47:31Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ics
  - vulnerability
  - scada
vendors:
  - ABB
  - Hitachi Energy
  - Johnson Controls
  - MAXHUB
products:
  - Automation Runtime
  - Automation Studio
  - PVI
  - PCM600
  - CEM AC2000
  - Pivot Client Application
references:
  - https://cyber.gc.ca/en/alerts-advisories/control-systems-cisa-ics-security-advisories-av26-441
  - https://www.cisa.gov/news-events/cybersecurity-advisories
rules:
  - title: Detect ABB B&R Automation Studio Process Creation
    description: Detects process creation related to ABB B&R Automation Studio, potentially indicating unauthorized use or malicious activity.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Hitachi Energy PCM600 Process Creation
    description: Detects process creation related to Hitachi Energy PCM600, potentially indicating unauthorized use or malicious activity.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On May 11, 2026, CISA published multiple ICS advisories addressing security vulnerabilities in several industrial control systems and related products. The affected vendors include ABB, Hitachi Energy, Johnson Controls, and MAXHUB. The advisories cover a range of products, including ABB B&R Automation Runtime and Studio, ABB B&R PVI, Hitachi Energy PCM600, Johnson Controls CEM AC2000, and MAXHUB Pivot Client Application. These vulnerabilities could potentially allow attackers to compromise affected systems, leading to disruption of industrial processes, unauthorized access, or data breaches. The advisories urge users and administrators to review the specific details for each product, apply suggested mitigations, and install available updates to remediate the identified risks.

## Attack Chain

Due to the breadth of products covered and lack of specific vulnerability details, a generalized attack chain is described below, which may vary based on the specific vulnerability and product:

1. **Initial Access:** An attacker identifies a vulnerable ICS product exposed to a network.
2. **Vulnerability Exploitation:** The attacker exploits a vulnerability in the targeted product.
3. **Privilege Escalation:** The attacker escalates privileges within the compromised system.
4. **Lateral Movement:** The attacker moves laterally to other systems within the ICS network.
5. **Data Collection:** The attacker gathers sensitive information about the ICS environment and processes.
6. **System Manipulation:** The attacker manipulates ICS parameters or control logic.
7. **Denial of Service:** The attacker causes a denial-of-service condition, disrupting industrial operations.
8. **Impact:** The attack results in disruption of industrial processes, equipment damage, or safety incidents.

## Impact

Successful exploitation of vulnerabilities in ICS products can have significant consequences, including disruption of critical infrastructure, financial losses, safety hazards, and reputational damage. The specific impact depends on the nature of the targeted system and the attacker's objectives. While the number of affected installations is unknown, the widespread use of these products in various industries suggests a potentially broad attack surface. Failure to apply necessary updates and mitigations could leave organizations vulnerable to attacks targeting these known weaknesses.

## Recommendation

*   Review the CISA ICS advisories linked in the references for detailed information on each affected product.
*   Apply the suggested mitigations and necessary updates for ABB B&R Automation Runtime (versions prior to 6.5 and prior to R4.93), ABB B&R Automation Studio (versions prior to 6.5), ABB B&R PVI (versions prior to 6.5.0), Hitachi Energy PCM600 (multiple versions), Johnson Controls CEM AC2000 (versions 12.0, 11.0 and 10.6), and MAXHUB Pivot Client Application (versions prior to v1.36.2).
*   Monitor network traffic for suspicious activity related to the affected products (network_connection log source).
*   Implement strong access controls and network segmentation to limit the potential impact of a successful attack.
