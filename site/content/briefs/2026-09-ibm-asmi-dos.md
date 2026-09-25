---
title: Denial of Service Vulnerability in IBM Server Firmware ASMI
slug: 2026-09-ibm-asmi-dos
description: An unauthenticated remote attacker can cause a denial of service on the IBM Advanced System Management Interface (ASMI) by sending malformed HTTPS requests, triggering a crash and repeated interface restarts.
date: "2026-09-25T18:54:33Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:ibm:server_firmware:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - firmware
  - network-security
vendors:
  - IBM
products:
  - Server Firmware (FW1120.00-FW1120.01, FW1110.00-FW1110.31, FW1060.00-FW1060.81, FW950.00-FW950.H3)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated attacker on the management network can send a malformed HTTPS request to ASMI, causing the web server to crash with possible memory corruption.
    confidence_band: high
cves:
  - id: CVE-2026-93306
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93306
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Restrict network access to ASMI interfaces via ACLs.
      owner: IT Operations
      due: 24h
      evidence: Source indicates vulnerability is reachable via the management network.
  mitigation_plan:
    - priority: immediate
      action: Upgrade IBM Server Firmware to a non-vulnerable version.
      owner: IT Operations
      addresses: CVE-2026-93306
      evidence: Source identifies firmware version ranges as vulnerable.
---

IBM Server Firmware, specifically versions FW1120.00 through FW1120.01, FW1110.00 through FW1110.31, FW1060.00 through FW1060.81, and FW950.00 through FW950.H3, contains a vulnerability in the Advanced System Management Interface (ASMI) web interface. This flaw allows an unauthenticated attacker positioned on the management network to send malformed HTTPS requests to the ASMI endpoint. These requests cause the web server component to crash, leading to potential memory corruption and the generation of error logs. Although the ASMI interface is designed to restart automatically, an attacker can persistently send these requests to sustain the denial-of-service condition, effectively preventing administrative access to the server management functions. This vulnerability impacts the availability and integrity of the management plane for affected IBM server hardware.

## Impact

Successful exploitation results in a denial of service for the ASMI management interface. While the impact is limited to the management plane rather than the host operating system, continuous exploitation prevents administrators from monitoring server health, adjusting power settings, or performing out-of-band management operations. This vulnerability affects enterprise environments utilizing IBM servers with the vulnerable firmware versions listed.

## Recommendation

Prioritized actions for security operations and IT teams:

* Apply the firmware updates provided by IBM for all affected server hardware to remediate CVE-2026-93306.
* Implement strict network segmentation and access control lists (ACLs) to ensure the ASMI management interface is only accessible from hardened, trusted administrative workstations.
* Monitor network traffic logs for an unusual volume of HTTP error codes (e.g., 400 Bad Request or 500 Internal Server Error) or recurring connection resets directed toward the ASMI IP address range, which may indicate exploitation attempts.
