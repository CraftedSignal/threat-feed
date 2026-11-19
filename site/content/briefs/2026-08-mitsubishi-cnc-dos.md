---
brief_id: brief-2026-08-mitsubishi-cnc-dos
event_id: brief-2026-08-mitsubishi-cnc-dos
revision: 2
activity_at: "2026-11-19T17:09:40Z"
revision_history:
  - revision: 2
    at: "2026-11-19T17:09:40Z"
    checksum: sha256:2a045db90aeca7b9109702e131b527aa4c81bbf087fc8ff3bd0ef975aa767576
    summary: added CVE-2025-2399
    changed_fields:
      - cve_verification
      - cves
      - lastmod
      - updates
    source_urls:
      - https://www.cisa.gov/news-events/ics-advisories/icsa-26-078-05
title: Denial of Service Vulnerability in Mitsubishi Electric CNC Series
slug: 2026-08-mitsubishi-cnc-dos
description: An out-of-bounds read vulnerability (CVE-2025-2399) in Mitsubishi Electric CNC Series controllers allows remote attackers to trigger a denial-of-service condition via crafted packets sent to TCP port 683.
date: "2026-08-27T16:06:18Z"
lastmod: "2026-11-19T17:06:53Z"
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
  validation_status: Validated against CISA advisory metadata
tags:
  - ics
  - dos
  - industrial-control-systems
  - critical-infrastructure
  - cve-2025-2399
vendors:
  - Mitsubishi Electric
products:
  - C80
  - E70
  - E80
  - M70V
  - M720VS
  - M720VW
  - M730VS
  - M730VW
  - M750VS
  - M750VW
  - M80
  - M800S
  - M800VS
  - M800VW
  - M800W
  - M80V
  - M80VW
  - M80W
cve_verification:
  CVE-2025-2399:
    status: verified
    source: nvd
    checked_at: 2026-11-19T17:06:53.670080545Z
cves:
  - id: CVE-2025-2399
    cvss: 5.9
    epss: 0.00582
    kev_status: "false"
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-078-05
  - https://www.cve.org/CVERecord?id=CVE-2025-2399
  - https://www.mitsubishielectric.com/fa/download/index.html
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - OT Security
  immediate_actions:
    - action: Restrict network access to TCP port 683 for all listed CNC devices
      owner: OT Security
      due: 24h
      evidence: CISA advisory mitigation recommendation
  mitigation_plan:
    - priority: immediate
      action: Patch firmware to designated versions
      owner: IT Operations
      addresses: CVE-2025-2399
      evidence: CISA advisory remediation section
updates:
  - at: "2026-11-19T17:06:53Z"
    level: L2
    summary: added CVE-2025-2399
    sources:
      - cisa
    source_urls:
      - https://www.cisa.gov/news-events/ics-advisories/icsa-26-078-05
---

## Overview

Mitsubishi Electric has disclosed a vulnerability (CVE-2025-2399) affecting multiple versions of its CNC Series controllers, including the M800V, M80V, M800, M80, E80, C80, and M70 series. The vulnerability is rooted in improper validation of indices, positions, or offsets (CWE-1285) within the input processing logic of the affected devices. 

By sending specially crafted packets to TCP port 683, a remote attacker can induce an out-of-bounds read, resulting in a denial-of-service (DoS) condition. This vulnerability poses a risk to critical manufacturing environments where these CNC controllers are deployed. Defenders should focus on isolating affected hardware from untrusted networks and restricting access to TCP port 683. Patches are available from Mitsubishi Electric, and organizations should prioritize updates to the specified versions (BC, FN, or LK, depending on the product series) or apply the recommended IP filtering and network segmentation mitigations.

## Impact

The successful exploitation of CVE-2025-2399 results in a denial-of-service, which in an industrial manufacturing context can lead to unplanned downtime, loss of production, and disruption of automated machining processes. The vulnerability is rated with a CVSS 3.1 score of 5.9 (Medium), reflecting that while exploitation is remote, it requires specific technical craft to trigger the DoS condition. The affected devices are deployed globally in the critical manufacturing sector.

## Recommendation

- Apply the vendor-provided firmware updates (version BC, FN, or LK) appropriate for the specific CNC controller model.
- Isolate CNC controller networks from the enterprise network using firewalls or VPNs to prevent unauthorized access to TCP port 683.
- Implement IP address filtering on the affected controllers using the manufacturer's built-in functions to restrict communication to known-authorized endpoints.
- Restrict physical access to CNC hardware and connected network infrastructure.
- Deploy network intrusion detection systems to alert on abnormal traffic patterns directed at TCP port 683.
