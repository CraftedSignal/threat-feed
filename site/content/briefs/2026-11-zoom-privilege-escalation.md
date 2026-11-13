---
brief_id: brief-2026-11-11-zoom-privilege-escalation
event_id: brief-2026-11-11-zoom-privilege-escalation
revision: 2
activity_at: "2026-11-13T15:02:15Z"
revision_history:
  - revision: 2
    at: "2026-11-13T15:02:15Z"
    checksum: sha256:601351f3cff3f759b855613bb3d003fa490e727eb7126fb7fe0a941ca7fc4217
    summary: added CVE-2026-108186 +1; OS windows
    changed_fields:
      - affected_os
      - claim_state
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://www.ncsc.nl/alerts/kwetsbaarheden-in-zoom-workplace-voor-windows-update-nu
title: 'Zoom Workplace: Multiple vulnerabilities allowing privilege escalation'
slug: 2026-11-zoom-privilege-escalation
description: Zoom Workplace is affected by multiple vulnerabilities that allow a remote, anonymous attacker to perform privilege escalation.
date: "2026-11-11T15:54:17Z"
lastmod: "2026-11-13T15:01:01Z"
type: advisory
claim_state: <nil>
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
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Ein entfernter, anonymer Angreifer kann mehrere Schwachstellen in Zoom Video Communications Workplace ausnutzen, um seine Privilegien zu erhöhen.
    confidence_band: high
cves:
  - id: CVE-2026-108186
    kev_status: unknown
  - id: CVE-2026-108187
    kev_status: unknown
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4496
  - https://www.ncsc.nl/alerts/kwetsbaarheden-in-zoom-workplace-voor-windows-update-nu
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
updates:
  - at: "2026-11-13T15:01:01Z"
    level: L2
    summary: added CVE-2026-108186 +1; OS windows
    sources:
      - ncsc-nl
    source_urls:
      - https://www.ncsc.nl/alerts/kwetsbaarheden-in-zoom-workplace-voor-windows-update-nu
---

Zoom Video Communications Workplace is affected by multiple vulnerabilities that can be exploited by a remote, anonymous attacker to perform privilege escalation. Specific technical details and affected version ranges are not provided in the source report.

## Recommendation

- Monitor official Zoom security bulletins for updates and patch availability.
