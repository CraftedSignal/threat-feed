---
title: Rockwell Automation Communication Modules Denial-of-Service Vulnerability
slug: 2026-07-rockwell-automation-dos
description: A denial-of-service vulnerability (CVE-2026-9653) in Rockwell Automation 1756-EN2, 1756-EN3, and 1756-ENBT communication modules, due to improper validation of CIP Implicit Connection packets, allows an unauthenticated network attacker to continuously disrupt device connections.
date: "2026-07-16T16:16:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - industrial-control-systems
  - ics
  - ot
  - vulnerability
  - denial-of-service
  - rockwell-automation
vendors:
  - Rockwell Automation
products:
  - 1756-EN2 <=V12.001
  - 1756-EN3 <=V12.001
  - 1756-ENBT V6.006
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A denial-of-service security issue exists across all the 1756-EN2, EN3, and ENBT communication module due to improper validation of CIP Implicit Connection packets. An attacker on the network can exploit this by sending crafted packets to continuously disrupt device connections
    confidence_band: high
cves:
  - id: CVE-2026-9653
    epss: 0.00178
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-197-02
  - https://www.cve.org/CVERecord?id=CVE-2026-9653
---

CISA has issued an advisory regarding CVE-2026-9653, a denial-of-service vulnerability affecting Rockwell Automation 1756-EN2, 1756-EN3, and 1756-ENBT communication modules. This flaw stems from improper validation of Common Industrial Protocol (CIP) Implicit Connection packets. An unauthenticated attacker with network access can exploit this by sending specially crafted packets to the vulnerable modules, leading to a continuous disruption of device connections. Although connections will recover immediately after each disruption, persistent attacks can cause significant operational instability in industrial control systems. The vulnerability affects 1756-EN3 firmware versions up to V12.001, 1756-EN2 firmware versions up to V12.001, and 1756-ENBT firmware version V6.006. While no public exploitation has been reported at the time of the advisory, the vulnerability poses a high risk to critical manufacturing operations globally.

## Attack Chain

1. An attacker establishes network access to the target Rockwell Automation 1756-EN2, 1756-EN3, or 1756-ENBT communication module.
2. The attacker crafts malicious Common Industrial Protocol (CIP) Implicit Connection packets designed to trigger the vulnerability.
3. The attacker sends these specially malformed packets across the network to the vulnerable module.
4. The communication module, due to improper validation of the integrity check value within the incoming packets, fails to process them correctly.
5. This malformed packet handling causes the communication module to enter a denial-of-service state, disrupting its active connections.
6. The attacker continues to send crafted packets, causing continuous disruption of device connections and instability in the industrial control system.
7. The final objective is to disrupt critical manufacturing processes by rendering the communication modules inoperable or unreliable.

## Impact

Successful exploitation of CVE-2026-9653 could lead to a continuous denial-of-service condition affecting Rockwell Automation 1756-EN2, 1756-EN3, and 1756-ENBT communication modules. While device connections recover immediately after each disruption, an attacker can persistently send crafted packets, causing ongoing operational instability and intermittent loss of communication within critical industrial control systems. This could lead to disruptions in critical manufacturing sectors worldwide. No specific number of victims has been reported, but these modules are widely deployed globally.

## Recommendation

* Update Rockwell Automation 1756-EN3 modules to V12.002 or later to mitigate CVE-2026-9653.
* Update Rockwell Automation 1756-EN2 modules to V12.002 or later to mitigate CVE-2026-9653.
* Minimize network exposure for all control system devices, including Rockwell Automation 1756-ENBT (which has no patch for CVE-2026-9653), by ensuring they are not accessible from the internet. Log sources like `network_connection` and `firewall` can help monitor access attempts.
* Isolate control system networks from business networks and place them behind firewalls.
* For remote access, utilize Virtual Private Networks (VPNs) and ensure they are updated to the most current version available.
