---
brief_id: brief-2026-11-10-windows-webshell-strings
event_id: brief-2026-11-10-windows-webshell-strings
revision: 1
activity_at: "2026-11-10T03:35:22Z"
title: Detection of Windows Webshell Activity via Web Server Logs
slug: 2026-11-windows-webshell-strings
description: This brief provides detection logic for common Windows command-line utilities and shell-spawning techniques observed in web server access logs associated with webshell exploitation.
date: "2026-11-10T03:35:22Z"
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
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Detection logic verified against standard web logging patterns
tags:
  - webshell
  - web-application
  - command-execution
  - persistence
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    subtechnique_id: T1505.003
    subtechnique_name: Web Shell
    evidence: Detects common commands used in Windows webshells
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_win_webshells_in_access_logs.yml
rules:
  - title: Detect Windows Webshell Command Execution via Webserver Logs
    description: Detects GET requests containing common Windows command-line utilities and parameters indicative of webshell interaction
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to monitor web access logs for command execution patterns
      owner: Detection Engineering
      due: 48h
      evidence: Source provides patterns for common Windows utilities
  hunt_leads:
    - lead: Identify high-frequency GET requests to web applications containing Windows-specific command keywords
      technique_id: T1505.003
      data_needed:
        - Web server access logs (cs-uri-query, cs-method, c-ip, cs-user-agent)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Analysis of access logs can reveal historical webshell interaction
---

This intelligence identifies common strings associated with Windows-based webshell interaction, typically seen in the query parameters of GET requests targeting compromised web applications. The provided detection logic aims to identify post-exploitation activity where an adversary uses the web server to execute system commands.

## Recommendation
- Deploy the provided Sigma rule to your SIEM, ingesting web server access logs (e.g., W3C format).
- Review historical logs for the identified command strings to scope potential past compromises.
- Tune the detection to exclude internal documentation sites or administrative consoles that legitimately process command strings in query parameters.
