---
title: Denial of Service Vulnerabilities in Rockwell Automation RSLinx Classic
slug: 2026-09-rockwell-rslinx-dos
description: Multiple vulnerabilities in Rockwell Automation RSLinx Classic allow an unauthenticated remote attacker to cause a denial-of-service condition via specially crafted CIP packets.
date: "2026-09-01T17:10:44Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:rockwell_automation:rslinx_classic:*:*:*:*:*:*:*:*
tags:
  - ics
  - ot
  - denial-of-service
  - vulnerability
vendors:
  - Rockwell Automation
products:
  - RSLinx Classic (<=4.50)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A crafted CIP packet can cause the RSLinx Classic service to crash, requiring a restart of the service to recover.
    confidence_band: high
cves:
  - id: CVE-2026-9621
  - id: CVE-2026-9622
  - id: CVE-2026-9624
  - id: CVE-2026-9625
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-244-01
  - https://www.cve.org/CVERecord?id=CVE-2026-9621
  - https://www.cve.org/CVERecord?id=CVE-2026-9622
  - https://www.cve.org/CVERecord?id=CVE-2026-9624
  - https://www.cve.org/CVERecord?id=CVE-2026-9625
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - OT Security
  immediate_actions:
    - action: Upgrade RSLinx Classic to 4.60 or later
      owner: IT Operations
      due: 72h
      evidence: Vendor fix in source advisory
  mitigation_plan:
    - priority: immediate
      action: Restrict access to CIP port 44818 at the network perimeter
      owner: OT Security
      addresses: CVE-2026-9621, CVE-2026-9622, CVE-2026-9624, CVE-2026-9625
      evidence: Mitigation guidance in source advisory
---

Rockwell Automation RSLinx Classic versions 4.50 and earlier are affected by multiple memory-related vulnerabilities, specifically identified as CVE-2026-9621, CVE-2026-9622, CVE-2026-9624, and CVE-2026-9625. These vulnerabilities stem from improper handling and insufficient validation of malformed or oversized Common Industrial Protocol (CIP) packets sent to the RSLinx Classic service. 

When processed, these malformed packets can trigger integer overflows, underflows, or buffer overflows within the RSLinx service, resulting in an unrecoverable service crash. Successful exploitation results in a denial-of-service condition, necessitating a manual restart of the affected service to restore functionality. This is particularly concerning in Industrial Control System (ICS) environments where availability is critical for operational technology (OT) process monitoring and communication. Attackers can exploit these flaws remotely without authentication, targeting the Industrial Manufacturing sector.

## Impact

Successful exploitation of these vulnerabilities leads to a complete denial-of-service of the RSLinx Classic service. This prevents legitimate communication between industrial applications and field devices, potentially disrupting industrial control processes. Given the lack of authentication required, the impact is considered high in critical manufacturing environments.

## Recommendation

- Upgrade all instances of RSLinx Classic to version 4.60 or later to remediate CVE-2026-9621, CVE-2026-9622, CVE-2026-9624, and CVE-2026-9625.
- If upgrading is not immediately feasible, implement firewall restrictions to limit access to the RSLinx Classic service (typically running over CIP/EtherNet/IP, port 44818) to only trusted engineering workstations or authorized communication sources.
- Consult Rockwell Automation security best practices (A_ID/1085012) for hardening guidance in OT environments.
