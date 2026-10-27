---
brief_id: brief-2026-10-27-nomachine-rce
event_id: brief-2026-10-27-nomachine-rce
revision: 1
activity_at: "2026-10-27T17:35:26Z"
title: 'NoMachine: Remote Code Execution vulnerability'
slug: 2026-10-nomachine-rce
description: A vulnerability in NoMachine allows a remote, unauthenticated attacker to execute arbitrary code on the target system.
date: "2026-10-27T17:35:26Z"
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
  validation_status: Needs environment verification
tags:
  - remote-code-execution
  - vulnerability
vendors:
  - NoMachine
products:
  - NoMachine
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4174
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Identify and inventory all internal servers and workstations running the NoMachine software
      owner: IT Operations
      due: 24h
  hunt_leads:
    - lead: Monitor for suspicious child processes spawned by nxserver or associated NoMachine daemon processes
      data_needed:
        - Endpoint process creation logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The source indicates the vulnerability allows remote code execution on the target system.
  mitigation_plan:
    - priority: immediate
      action: Monitor the official NoMachine vendor advisory page for a patch and deploy to all affected assets
      owner: IT Operations
      addresses: NoMachine software
      evidence: The BSI advisory confirms a vulnerability exists and requires patching.
---

A vulnerability in NoMachine allows a remote, unauthenticated attacker to execute arbitrary code. The BSI advisory notes that the vulnerability can be exploited by an anonymous attacker, but specific CVE identifiers or technical details regarding the vulnerability class were not disclosed in the initial advisory.

## Impact
Successful exploitation allows for arbitrary code execution on systems running the affected NoMachine software.

## Recommendation
- Inventory all systems running NoMachine across the environment.
- Monitor NoMachine services for the spawning of unexpected child processes or abnormal outbound network connections.
- Review official NoMachine security update channels for patch availability and apply updates immediately upon release.
