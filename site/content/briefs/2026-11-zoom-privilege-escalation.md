---
brief_id: brief-2026-11-11-zoom-privilege-escalation
event_id: brief-2026-11-11-zoom-privilege-escalation
revision: 1
activity_at: "2026-11-11T15:54:17Z"
title: 'Zoom Workplace: Multiple vulnerabilities allowing privilege escalation'
slug: 2026-11-zoom-privilege-escalation
description: Zoom Workplace is affected by multiple vulnerabilities that allow a remote, anonymous attacker to perform privilege escalation.
date: "2026-11-11T15:54:17Z"
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
vendors:
  - Zoom
products:
  - Zoom Workplace
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Ein entfernter, anonymer Angreifer kann mehrere Schwachstellen in Zoom Video Communications Workplace ausnutzen, um seine Privilegien zu erhöhen.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4496
action_plan:
  hunt_leads:
    - lead: Identify child processes spawned by Zoom-related executables (e.g., Zoom.exe) that execute with higher integrity levels or user context than the parent process, specifically monitoring for unusual command-line arguments or binary paths.
      technique_id: T1068
      data_needed:
        - Process Creation logs (ParentProcessName, ProcessName, IntegrityLevel, CommandLine)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Ein entfernter, anonymer Angreifer kann mehrere Schwachstellen in Zoom Video Communications Workplace ausnutzen, um seine Privilegien zu erhöhen.
---

Zoom Video Communications Workplace is affected by multiple vulnerabilities that can be exploited by a remote, anonymous attacker to perform privilege escalation. Specific technical details and affected version ranges are not provided in the source report.

## Recommendation

- Monitor official Zoom security bulletins for updates and patch availability.
