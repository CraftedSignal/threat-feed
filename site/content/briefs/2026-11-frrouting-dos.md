---
brief_id: brief-2026-11-13-frrouting-dos
event_id: brief-2026-11-13-frrouting-dos
revision: 1
activity_at: "2026-11-13T16:11:56Z"
title: 'FRRouting: Denial of Service vulnerability'
slug: 2026-11-frrouting-dos
description: A vulnerability in the FRRouting suite allows a remote authenticated attacker to trigger a denial-of-service condition.
date: "2026-11-13T16:11:56Z"
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
  validation_status: needs_environment_validation
vendors:
  - FRRouting
products:
  - FRRouting
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Ein entfernter, authentisierter Angreifer kann eine Schwachstelle in FRRouting ausnutzen, um einen Denial of Service Angriff durchzuführen.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4548
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Network Engineering
  immediate_actions:
    - action: Inventory all network devices currently running FRRouting
      owner: Network Engineering
      due: 48h
      evidence: The advisory indicates a vulnerability in FRRouting, requiring identification of all vulnerable instances.
  hunt_leads:
    - lead: Monitor FRRouting logs for repeated authentication attempts followed by service instability or crashes
      technique_id: T1498
      data_needed:
        - FRRouting daemon logs
        - System service status logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability requires authentication, making abnormal authentication behavior followed by service impact a primary hunt indicator.
---

The BSI has published a security advisory regarding a vulnerability in FRRouting that permits a remote, authenticated attacker to cause a denial-of-service (DoS) condition. Details regarding the underlying vulnerability class or the specific mechanism of exploitation remain undisclosed in the current notice.

## Impact

Successful exploitation results in a denial-of-service state for the affected routing suite, potentially disrupting network traffic routing and connectivity for dependent systems.

## Recommendation

1. Inventory all systems running FRRouting to assess the exposure of the routing infrastructure.
2. Monitor the official FRRouting project website and BSI security portal for the release of patches or mitigation guidance.
3. Verify that access control lists (ACLs) are configured to restrict administrative access to the FRRouting interface to trusted management sources only, as the vulnerability requires authentication.
