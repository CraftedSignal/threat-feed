---
brief_id: brief-2026-10-28-n8n-privilege-escalation
event_id: brief-2026-10-28-n8n-privilege-escalation
revision: 1
activity_at: "2026-10-28T20:38:29Z"
title: 'n8n: Unauthorized credential access via error workflow execution (CVE-2026-118644)'
slug: 2026-10-n8n-privilege-escalation
description: A vulnerability in n8n allows a project editor to intercept a colleague's failed workflow execution context and assume their identity to resolve per-user dynamic credential secrets.
date: "2026-10-28T20:38:29Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
products:
  - n8n (< 2.41.5, 2.42.x < 2.42.2)
cves:
  - id: CVE-2026-118644
    cvss: 7.7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118644
---

A vulnerability exists in n8n where a failed workflow's full execution context, including the identity of the user who started the run, is passed to the configured error workflow. A project editor can set a colleague's `settings.errorWorkflow` to an error workflow they own. When the colleague's workflow fails, the attacker can inherit the colleague's identity and resolve the colleague's per-user dynamic credential secrets. This affects n8n before 2.41.5 and 2.42.x before 2.42.2.
