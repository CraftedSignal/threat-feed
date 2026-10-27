---
brief_id: brief-2026-10-27-johnson-controls-kantech-entrapass
event_id: brief-2026-10-27-johnson-controls-kantech-entrapass
revision: 1
activity_at: "2026-10-27T23:46:14Z"
title: Johnson Controls Kantech Entrapass vulnerabilities
slug: 2026-10-johnson-controls-kantech-entrapass
description: Johnson Controls has released a security advisory addressing two vulnerabilities in Kantech Entrapass versions prior to 9.20.
date: "2026-10-27T23:46:14Z"
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
  validation_status: Validated against CCCS source material.
tags:
  - vulnerability
  - industrial-control-systems
  - informational
vendors:
  - Johnson Controls
products:
  - Kantech Entrapass (< 9.20)
references:
  - https://cyber.gc.ca/en/alerts-advisories/control-systems-johnson-controls-security-advisory-av26-1090
  - https://tyco.widen.net/s/m2wrtpljps/jci-psa-2026-21
  - https://www.johnsoncontrols.com/trust-center/cybersecurity/security-advisories
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Kantech Entrapass to version 9.20 or later
      owner: IT Operations
      addresses: Kantech Entrapass (< 9.20)
      evidence: Johnson Controls has confirmed two vulnerabilities impacting Kantech Entrapass
---

Johnson Controls has confirmed two vulnerabilities impacting Kantech Entrapass software. These vulnerabilities affect all versions prior to 9.20. Detailed technical information and specific CVE identifiers were not disclosed in the initial advisory; users are directed to the Johnson Controls Trust Center for further updates and remediation guidance.

## Recommendation

- Inventory all systems running Kantech Entrapass within the environment.
- Review the Johnson Controls product security advisory (PSA-2026-21) to determine the specific risk and requirements for your environment.
- Plan and execute an upgrade to Kantech Entrapass version 9.20 or later for all affected installations.
