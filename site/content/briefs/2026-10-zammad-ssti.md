---
brief_id: brief-2026-10-30-zammad-ssti
event_id: brief-2026-10-30-zammad-ssti
revision: 1
activity_at: "2026-10-30T18:01:03Z"
title: 'Zammad: Server-Side Template Injection remote code execution (CVE-2026-34724)'
slug: 2026-10-zammad-ssti
description: An authenticated administrator can exploit a Server-Side Template Injection (SSTI) vulnerability in the Zammad AI Agent feature to achieve remote code execution via the type_enrichment_data configuration.
date: "2026-10-30T18:01:03Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:zammad:zammad:7.0.0:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - ssti
  - webserver
vendors:
  - Zammad
products:
  - Zammad (< 7.0.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Server-Side Template Injection (SSTI) vulnerability in the new AI Agent feature.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An authenticated administrator... can inject malicious templates, leading to full Remote Code Execution (RCE).
    confidence_band: high
cves:
  - id: CVE-2026-34724
    cvss: 7.2
    epss: 0.00314
    kev_status: "false"
references:
  - https://github.com/zammad/zammad/security/advisories/GHSA-fg9w-jg8f-4j94
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-0XBLACKASH-CVE-2026-34724
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-0XBLACKASH-CVE-2026-34724&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Zammad type_enrichment_data Modification
    description: Detects administrative updates to the AI Agent type_enrichment_data configuration, which is the vector for CVE-2026-34724.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Zammad instances to version 7.0.1 or 6.5.4.
      owner: IT Operations
      due: 24h
      evidence: Official fix provided in Zammad 7.0.1.
  hunt_leads:
    - lead: Identify administrative accounts accessing the AI Agent configuration.
      technique_id: T1190
      data_needed:
        - Zammad audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability is limited to authenticated admin users.
  mitigation_plan:
    - priority: immediate
      action: Disable AI Agent feature if patching is delayed.
      owner: IT Operations
      addresses: CVE-2026-34724
      evidence: Source advises disabling feature as a temporary workaround.
---

CVE-2026-34724 is a Server-Side Template Injection (SSTI) vulnerability identified in the Zammad helpdesk software's AI Agent feature. The vulnerability allows an authenticated administrator to inject arbitrary templates into the 'type_enrichment_data' configuration, which are subsequently rendered, leading to full Remote Code Execution (RCE) on the server. The vulnerability is confirmed in Zammad version 7.0.0 and is remediated in version 7.0.1.

## Impact

Successful exploitation allows an authenticated attacker with administrative privileges to execute arbitrary commands on the underlying server as the process user (typically 'zammad' or 'www-data').

## Recommendation

* Upgrade Zammad installations to version 7.0.1 or 6.5.4 immediately.
* If patching is not feasible, disable the AI Agent feature in the Zammad configuration.
* Review administrative access controls and restrict access to the 'type_enrichment_data' configuration to highly trusted personnel only.
* Monitor Zammad system logs for unauthorized changes to administrative configuration parameters, specifically 'type_enrichment_data'.
