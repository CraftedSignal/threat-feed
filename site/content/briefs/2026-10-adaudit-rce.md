---
brief_id: brief-2026-10-30-adaudit-rce
event_id: brief-2026-10-30-adaudit-rce
revision: 1
activity_at: "2026-10-30T21:03:15Z"
title: 'ManageEngine ADAudit Plus: Pre-authentication remote code execution (CVE-2026-6516)'
slug: 2026-10-adaudit-rce
description: A public exploit and scanner have been published for CVE-2026-6516, a pre-authentication remote code execution vulnerability in ManageEngine ADAudit Plus Agent APIs.
date: "2026-10-30T21:03:15Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
vendors:
  - ManageEngine
products:
  - ADAudit Plus
  - Windows Agents
  - macOS Agents
cves:
  - id: CVE-2026-6516
    cvss: 10
    epss: 0.04729
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=A0C3FAF0-71CD-5B13-8AE7-A9250EE3C5CC
  - https://sploitus.com/exploit?id=A0C3FAF0-71CD-5B13-8AE7-A9250EE3C5CC&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review vendor advisory and apply recommended updates for ADAudit Plus and associated agents.
      owner: IT Operations
  hunt_leads:
    - lead: Identify Agent API endpoints responding without authentication.
      technique_id: T1190
      priority: high
      confidence: high
      evidence: The vulnerability exists within the Agent API surface.
---

CVE-2026-6516 is a pre-authentication remote code execution vulnerability in the Agent APIs of ManageEngine ADAudit Plus. The vulnerability involves authentication bypass and path traversal, potentially allowing an unauthenticated attacker to write files outside of the intended directory. The vulnerability is reported with a CVSS v3.1 base score of 10.0. A public scanner is available to identify Agent API endpoints that are reachable without authentication.
