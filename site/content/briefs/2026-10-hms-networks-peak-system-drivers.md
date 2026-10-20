---
brief_id: brief-2026-10-20-hms-networks-peak-system-drivers
event_id: brief-2026-10-20-hms-networks-peak-system-drivers
revision: 1
activity_at: "2026-10-20T17:31:22Z"
title: HMS Networks PEAK-System Windows Drivers Multiple Vulnerabilities
slug: 2026-10-hms-networks-peak-system-drivers
description: Multiple memory corruption and validation vulnerabilities in HMS Networks PEAK-System Windows drivers allow local attackers to induce a system kernel crash.
date: "2026-10-20T17:31:22Z"
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
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified; advisory confirms fixed version 5.1.4
tags:
  - industrial-control-systems
  - denial-of-service
  - driver-vulnerability
vendors:
  - HMS Networks
products:
  - PEAK-System Device Driver Setup (<=5.1.2.1151)
  - PCAN Windows CAN device drivers (<=5.1.2)
affected_os:
  - Windows
cves:
  - id: CVE-2026-101103
    kev_status: unknown
  - id: CVE-2026-103672
    kev_status: unknown
  - id: CVE-2026-105960
    kev_status: unknown
  - id: CVE-2026-109576
    kev_status: unknown
  - id: CVE-2026-110322
    kev_status: unknown
  - id: CVE-2026-94188
    kev_status: unknown
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-293-01
  - https://www.cve.org/CVERecord?id=CVE-2026-109576
  - https://www.cve.org/CVERecord?id=CVE-2026-101103
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade HMS Networks PEAK-System drivers to version 5.1.4 or later
      owner: IT Operations
      due: 48h
      evidence: HMS Networks AB has addressed the issue in version 5.1.4
  mitigation_plan:
    - priority: immediate
      action: Upgrade vulnerable driver versions
      owner: IT Operations
      addresses: CVE-2026-109576, CVE-2026-101103, CVE-2026-94188, CVE-2026-103672, CVE-2026-110322, CVE-2026-105960
      evidence: HMS advisory recommendation
---

HMS Networks has identified multiple critical security vulnerabilities affecting the PEAK-System Device Driver Setup (versions 5.1.2.1151 and earlier) and PCAN Windows CAN device drivers (versions 5.1.2 and earlier). These vulnerabilities, including out-of-bounds write (CWE-787), buffer overflow (CWE-120), and improper pointer dereferencing, arise from flaws in input handling, length parameter validation, and array indexing within the driver IOCTL and write paths. An attacker with local access to a system running these drivers can exploit these flaws by sending specifically crafted input to the driver, resulting in a denial-of-service condition via a Windows kernel crash. This represents a significant risk for systems integrated within critical infrastructure sectors, including energy, transportation, and manufacturing, where the stability of CAN bus communications is paramount.

## Impact

Successful exploitation of these vulnerabilities leads to a Windows kernel crash, resulting in a denial-of-service for the affected host and the associated industrial control system process. These drivers are globally deployed in critical sectors such as Transportation, Healthcare, Energy, and Critical Manufacturing. If the driver is hosting a critical control process, a crash could lead to a temporary loss of industrial process visibility or control.

## Recommendation

1. Upgrade all instances of the PEAK-System Device Driver Setup and PCAN Windows CAN device drivers to version 5.1.4 or later immediately.
2. Audit systems in critical infrastructure environments for the presence of PEAK-System drivers to determine exposure, focusing on hosts connected to CAN bus interfaces.
3. Restrict local access to systems with these drivers installed to prevent unauthorized users from interacting with the vulnerable driver IOCTL paths.
4. Monitor system event logs for unexpected kernel-mode crashes or bug checks that correlate with software using the PEAK-System interface.
