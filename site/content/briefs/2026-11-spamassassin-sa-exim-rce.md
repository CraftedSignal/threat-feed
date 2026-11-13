---
brief_id: brief-2026-11-13-spamassassin-sa-exim-rce
event_id: brief-2026-11-13-spamassassin-sa-exim-rce
revision: 1
activity_at: "2026-11-13T10:00:42Z"
title: 'SpamAssassin sa-exim: Remote Code Execution'
slug: 2026-11-spamassassin-sa-exim-rce
description: A vulnerability in the sa-exim plugin for SpamAssassin allows an authenticated remote attacker to execute arbitrary code with administrator privileges within the Exim mail transfer agent environment.
date: "2026-11-13T10:00:42Z"
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
  verdict: pass_with_fixes
  validation_status: Awaiting vendor patch release and CVE ID for further scoping and detection development.
vendors:
  - Apache
products:
  - sa-exim
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Ein entfernter, authentisierter Angreifer kann eine Schwachstelle in sa-exim, dem SpamAssassin Filter für Exim, ausnutzen, um beliebigen Programmcode mit Administratorrechten auszuführen.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4543
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all mail servers currently running the sa-exim plugin.
      owner: IT Operations
      due: 24h
  hunt_leads:
    - lead: Monitor process execution logs for unexpected child processes spawned by the Exim or SpamAssassin service accounts.
      technique_id: T1190
      data_needed:
        - Endpoint Process Creation (Event ID 1 or auditd)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability allows execution of arbitrary code with administrator privileges within the context of the mail filtering integration.
---

A vulnerability exists in sa-exim, a plugin for the SpamAssassin email filtering system, which allows an authenticated remote attacker to execute arbitrary code with administrative privileges. The issue resides in the integration between the SpamAssassin filter and the Exim mail transfer agent.

## Impact

Successful exploitation allows an attacker to achieve remote code execution with administrative rights, potentially leading to full system compromise of the mail server.

## Recommendation

Given the high-severity nature of remote code execution, perform an immediate audit of systems running the sa-exim plugin. Monitor Exim logs for unusual process spawning or administrative command execution originating from the mail filter context.
