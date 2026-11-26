---
brief_id: brief-2026-11-26-rustdesk-privilege-escalation
event_id: brief-2026-11-26-rustdesk-privilege-escalation
revision: 1
activity_at: "2026-11-26T21:49:30Z"
title: 'RustDesk: Local privilege escalation to administrator'
slug: 2026-11-rustdesk-privilege-escalation
description: A local privilege escalation vulnerability exists in RustDesk, allowing a local attacker to execute arbitrary code with administrator privileges.
date: "2026-11-26T21:49:30Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Information extracted from BSI advisory; requires monitoring for upcoming vendor security updates.
vendors:
  - RustDesk
products:
  - RustDesk
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Ein lokaler Angreifer kann eine Schwachstelle in RustDesk ausnutzen, um beliebigen Programmcode mit Administratorrechten auszuführen.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4822
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all installations of RustDesk across the enterprise environment.
      owner: IT Operations
      due: 48h
      evidence: The vulnerability affects RustDesk and local access is a prerequisite for exploitation.
    - action: Monitor for official vendor security bulletins regarding this vulnerability.
      owner: CTI
      due: ongoing
      evidence: The source identifies the vulnerability as unpatched (UNGEPATCHT).
  hunt_leads:
    - lead: Investigate unusual process execution or privilege changes originating from the RustDesk service account or child processes.
      technique_id: T1068
      data_needed:
        - Process creation logs
        - Service logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability allows for code execution with administrator privileges via a local attack vector.
---

## Overview

A local privilege escalation vulnerability has been identified in RustDesk. The vulnerability allows a local attacker to execute arbitrary code with administrator privileges. As of the current advisory from BSI, no patch or mitigation details are provided.

## Impact

Successful exploitation allows a local attacker to elevate their privileges to the administrator level, potentially leading to full system compromise.

## Recommendation

- Monitor the vendor's official security channels for the release of a patch.
- Restrict local access to systems running RustDesk to authorized users only to mitigate the risk of local exploitation.
- Audit local user permissions on systems where RustDesk is deployed.
