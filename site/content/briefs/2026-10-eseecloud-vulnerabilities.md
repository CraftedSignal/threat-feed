---
title: Critical Vulnerabilities in Guangzhou Juan IoT Technology EseeCloud
slug: 2026-10-eseecloud-vulnerabilities
description: Multiple critical vulnerabilities in EseeCloud App and firmware allow remote, unauthenticated attackers to gain device control, perform unauthorized device rebinding, and perform bulk enumeration of registered IoT cameras.
date: "2026-10-15T17:00:33Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Guangzhou Juan IoT Technology Co., Ltd.
products:
  - EseeCloud App (<=4.9.6)
  - EseeCloud Firmware (<=4.9.86.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Successful exploitation of these vulnerabilities could allow an attacker to gain control over affected IP cameras.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: this discrepancy constitutes an enumeration oracle, enabling an attacker to discover registered devices at scale.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-288-02
  - https://www.cve.org/CVERecord?id=CVE-2026-107617
  - https://www.cve.org/CVERecord?id=CVE-2026-97858
  - https://www.cve.org/CVERecord?id=CVE-2026-105664
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Isolate EseeCloud cameras from public-facing network segments
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-107617, CVE-2026-97858, CVE-2026-105664
  hunt_leads:
    - lead: High-volume API requests for sequential device IDs to identifying registered cameras
      technique_id: T1592.001
      data_needed:
        - Web server logs for API endpoints
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: CVE-2026-105664 describes an enumeration oracle via response discrepancies
  mitigation_plan:
    - priority: immediate
      action: Contact vendor (https://eseecloud.app/) for support regarding available firmware updates
      owner: IT Operations
      addresses: CVE-2026-107617, CVE-2026-97858, CVE-2026-105664
      evidence: CISA advisory instruction for unpatched product
---

Guangzhou Juan IoT Technology EseeCloud products, including the EseeCloud App (versions <=4.9.6) and EseeCloud Firmware (versions <=4.9.86.0), are affected by three severe vulnerabilities (CVE-2026-107617, CVE-2026-97858, CVE-2026-105664). These flaws expose IP cameras to complete remote compromise. The vulnerabilities include the use of hard-coded credentials, a flaw allowing unauthorized modification of object attributes that enables device rebinding, and an enumeration oracle created by observable response discrepancies. Because the vendor has not responded to CISA coordination attempts, no official patches are currently available. These devices are widely deployed across energy, communications, transportation, financial, and government sectors, presenting a significant risk of large-scale IoT botnet recruitment or unauthorized surveillance.

## Attack Chain

1. An attacker identifies target EseeCloud devices via internet-wide scanning or OSINT discovery.
2. The attacker uses the enumeration oracle (CVE-2026-105664) by sending repeated API requests with incrementing ID values to identify valid, registered device IDs.
3. The attacker observes the response discrepancies (error codes) to filter out nonexistent IDs from the 10-digit numeric search space.
4. The attacker leverages the hard-coded credentials (CVE-2026-107617) to bypass standard authentication mechanisms.
5. The attacker issues a malicious request to the management API to unbind the target camera from the legitimate owner (CVE-2026-97858).
6. The attacker binds the target camera to an account under their control by exploiting improper attribute modification (CVE-2026-97858).
7. The attacker gains full control over the camera, including the ability to stream video, modify settings, or integrate the device into a botnet.

## Impact

Successful exploitation results in total loss of device integrity and confidentiality. Attackers can hijack existing EseeCloud IP cameras, potentially leading to unauthorized real-time surveillance of sensitive environments or the integration of thousands of cameras into distributed denial-of-service (DDoS) botnets. These vulnerabilities affect critical infrastructure sectors including energy, finance, and government, with deployment reported on a global scale.

## Recommendation

Prioritized, concrete actions for security operations:
- Network administrators should identify and isolate EseeCloud devices from the public internet using firewalls or dedicated IoT VLANs to prevent direct reachability.
- Monitor ingress traffic to management endpoints for high-frequency sequences of API requests that may indicate enumeration activity against device ID spaces (CVE-2026-105664).
- Since no patch is available, organizations should evaluate the business necessity of these devices and consider transitioning to supported, hardened hardware if potential exposure to these CVEs presents an unacceptable risk.
- Block access to the EseeCloud mobile/API traffic at the perimeter for non-essential use cases to mitigate the risk of unauthorized device rebinding.
