---
brief_id: brief-2026-11-13-siemens-security-advisory
event_id: brief-2026-11-13-siemens-security-advisory
revision: 1
activity_at: "2026-11-13T10:14:18Z"
title: 'Siemens: Multiple product security vulnerabilities'
slug: 2026-11-siemens-security-advisory
description: Siemens released security advisory AV26-1139 on November 10, 2026, announcing vulnerabilities across several industrial control and software systems, including the SIMATIC, Mendix, and RUGGEDCOM product lines.
date: "2026-11-13T10:14:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: No specific vulnerability details or exploitation behavior are documented in the source; remediation depends on vendor-provided updates.
tags:
  - vulnerability
  - industrial-control-systems
  - informational
vendors:
  - Siemens
products:
  - Mendix Studio Pro 11 (< V11.16.0)
  - Mendix Studio Pro 11.12 (< V11.12.7)
  - meta-iot2050 (V01.03.01)
  - ROS# (< V2.3.1)
  - RUGGEDCOM APE1808 (All versions)
  - SIMATIC BATCH V9.1 (All versions)
  - SIMATIC Information Server 2020 / 2022 (All versions)
  - SIMATIC PCS 7 V9.1 (All versions)
  - SIMATIC Process Historian 2020 / 2022 (All versions)
  - SIMATIC WinCC Runtime Professional V17 / V18 / V19 / V20 / V21 (All versions)
  - SIMATIC WinCC V7.5 / V8.0 / V8.1 (All versions)
  - Simcenter Femap (< V2606.0002)
references:
  - https://cyber.gc.ca/en/alerts-advisories/control-systems-siemens-security-advisory-av26-1139
  - https://www.siemens.com/en-us/content/cert-services/
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - OT Security
  immediate_actions:
    - action: Inventory environment for Siemens software and hardware listed in advisory AV26-1139
      owner: IT Operations
      due: 48h
      evidence: Advisory AV26-1139 impacts multiple Siemens product lines requiring administrator review.
  mitigation_plan:
    - priority: short_term
      action: Review Siemens CERT Services portal to identify and apply recommended security updates or workarounds
      owner: OT Security
      addresses: All listed Siemens products
      evidence: The Cyber Centre encourages users and administrators to review the provided web link and apply any necessary updates as they become available.
---

On November 10, 2026, Siemens published security advisory AV26-1139 detailing vulnerabilities affecting a broad range of its industrial automation software and hardware components. The advisory indicates that various versions of Mendix Studio Pro, ROS#, Simcenter Femap, and several iterations of the SIMATIC management and runtime environment are affected. Furthermore, hardware products including the meta-iot2050 and RUGGEDCOM APE1808 are listed as impacted. The source advisory does not detail specific vulnerability classes or exploitation methods at this time; users must consult the official Siemens CERT services portal to identify specific mitigation steps and fixed versions for their environment.

## Recommendation

* Inventory your environment for all Siemens products listed in the affected_products section.
* Review the official Siemens CERT Services advisory at https://www.siemens.com/en-us/content/cert-services/ to obtain detailed vulnerability impact assessments and identify specific patches or workarounds.
* Prioritize patching of internet-facing or mission-critical industrial control systems identified in the inventory.
