---
title: Critical Vulnerabilities in Rockwell Automation Historian ME
slug: 2026-09-rockwell-historian
description: Rockwell Automation Historian ME series B and C contain multiple vulnerabilities, including an out-of-bounds write allowing remote code execution and a buffer overflow causing denial-of-service.
date: "2026-09-01T17:10:53Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:rockwell_automation:historian_me:*:*:*:*:*:*:*:*
vendors:
  - Rockwell Automation
products:
  - Historian ME (Series B 5.202)
  - Historian ME (Series C 7.101)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An attacker with low-level authentication could exploit this vulnerability to achieve remote code execution on the affected device.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: A network adjacent attacker who is authenticated could send crafted requests to the web interface, resulting in buffer overflow conditions that may cause the device to crash and become unresponsive.
    confidence_band: high
cves:
  - id: CVE-2025-12768
  - id: CVE-2026-12661
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-244-06
  - https://www.cve.org/CVERecord?id=CVE-2025-12768
  - https://www.cve.org/CVERecord?id=CVE-2026-12661
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Isolate affected Historian ME devices behind firewalls and restrict web interface access
      owner: IT Operations
      due: 24h
      evidence: CISA recommendation to minimize network exposure for all control system devices
  mitigation_plan:
    - priority: immediate
      action: Contact Rockwell Automation TechConnect to obtain and apply security updates
      owner: IT Operations
      addresses: CVE-2025-12768, CVE-2026-12661
      evidence: Source remediation guidance for customers not able to immediately upgrade
---

Rockwell Automation has disclosed two vulnerabilities affecting FactoryTalk Historian Machine Edition (ME) versions Series B 5.202 and Series C 7.101. These vulnerabilities, tracked as CVE-2025-12768 and CVE-2026-12661, expose critical infrastructure to severe operational risks. CVE-2025-12768 is an out-of-bounds write vulnerability (CWE-787) that allows an authenticated attacker with low-level access to achieve remote code execution. CVE-2026-12661 is a stack-based buffer overflow (CWE-121) triggered by crafted requests sent to the web interface, which can lead to a device crash and denial-of-service conditions. These vulnerabilities impact diverse sectors, including water, healthcare, food production, and manufacturing. Given the critical nature of these industrial control systems, defenders must prioritize network isolation and ensure administrative access controls are rigorously enforced to prevent unauthorized exploitation.

## Impact

Successful exploitation of these vulnerabilities could result in full system compromise via remote code execution (CVE-2025-12768) or the loss of availability through forced device crashes (CVE-2026-12661). These systems are deployed in vital critical infrastructure sectors, including chemical processing, healthcare, and water systems. If compromised, attackers could potentially manipulate industrial processes or render safety-critical monitoring systems unresponsive. No known public exploitation has been reported as of September 2026.

## Recommendation

Prioritize the following actions to secure affected Rockwell Automation Historian ME environments:

* Immediately isolate all affected Historian ME controllers behind firewalls and restrict access to the web interface to authorized management subnets only.
* Contact Rockwell Automation TechConnect for guidance on obtaining and deploying the latest firmware or software patches for Series B 5.202 and Series C 7.101.
* Monitor network traffic to the device web interface for anomalous, malformed, or excessively large HTTP requests that may indicate exploitation attempts for CVE-2026-12661.
* Review all existing authenticated user accounts on the affected Historian ME devices to identify and disable unauthorized or dormant low-level accounts that could be leveraged for CVE-2025-12768.
