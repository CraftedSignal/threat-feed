---
brief_id: brief-2026-10-21-mattermost-vulnerabilities
event_id: brief-2026-10-21-mattermost-vulnerabilities
revision: 1
activity_at: "2026-10-21T16:07:25Z"
title: 'Mattermost Server: Multiple security vulnerabilities'
slug: 2026-10-mattermost-vulnerabilities
description: Multiple unspecified vulnerabilities have been identified in Mattermost Server, requiring immediate review of vendor security bulletins and application of necessary patches.
date: "2026-10-21T16:07:25Z"
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
tags:
  - vulnerability
  - security-update
vendors:
  - Mattermost
products:
  - Mattermost Server (11.10.x < 11.10.3)
  - Mattermost Server (11.11.x < 11.11.2)
  - Mattermost Server (11.7.x < 11.7.13)
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1348/
  - https://mattermost.com/security-updates/
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Mattermost Server to the versions specified in the bulletin
      owner: IT Operations
      due: 48h
      evidence: Vulnerability disclosure requires software update for mitigation
  mitigation_plan:
    - priority: immediate
      action: Upgrade Mattermost Server to 11.10.3, 11.11.2, or 11.7.13 depending on the branch
      owner: IT Operations
      addresses: Mattermost Server versions 11.10.x, 11.11.x, and 11.7.x
      evidence: CERT-FR advisory CERTFR-2026-AVI-1348
---

The French National Cybersecurity Agency (ANSSI) has published an advisory regarding multiple unspecified vulnerabilities in Mattermost Server. These vulnerabilities, identified in Mattermost security bulletins MMSA-2026-00772 and MMSA-2026-00783, could allow an attacker to trigger unspecified security issues. Details regarding specific vulnerability types or exploitation vectors remain undisclosed by the vendor.

## Recommendation

* Inventory all internal Mattermost Server instances to identify versions 11.10.x, 11.11.x, and 11.7.x.
* Upgrade Mattermost Server instances to the following patched versions immediately:
 * Upgrade version 11.10.x to 11.10.3 or later.
 * Upgrade version 11.11.x to 11.11.2 or later.
 * Upgrade version 11.7.x to 11.7.13 or later.
* Monitor the official Mattermost Security Updates portal for further technical disclosures.
