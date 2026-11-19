---
brief_id: brief-2026-11-19-mattermost-dos
event_id: brief-2026-11-19-mattermost-dos
revision: 1
activity_at: "2026-11-19T15:36:54Z"
title: 'Mattermost: Denial of Service vulnerability'
slug: 2026-11-mattermost-dos
description: A vulnerability in Mattermost allows a remote, anonymous attacker to perform a Denial of Service (DoS) attack.
date: "2026-11-19T15:36:54Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
vendors:
  - Mattermost
products:
  - Mattermost
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Ein entfernter, anonymer Angreifer kann eine Schwachstelle in Mattermost ausnutzen, um einen Denial of Service Angriff durchzuführen.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4670
action_plan:
  hunt_leads:
    - lead: Identify anomalous spikes in Mattermost application-layer request volume or unexpected process crashes/restarts associated with remote unauthenticated connections.
      technique_id: T1499
      data_needed:
        - Mattermost access logs
        - Mattermost service error logs
        - System process monitoring logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Ein entfernter, anonymer Angreifer kann eine Schwachstelle in Mattermost ausnutzen, um einen Denial of Service Angriff durchzuführen.
---

## Overview

A vulnerability has been identified in Mattermost that allows a remote, anonymous attacker to cause a Denial of Service (DoS) condition. No specific version information, affected ranges, or technical details are currently available.

## Impact

The vulnerability allows an attacker to disrupt the availability of the Mattermost service.

## Recommendation

Organizations should monitor official Mattermost security channels and the BSI WID portal for updates or vendor-provided remediation information.
