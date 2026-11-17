---
brief_id: brief-2026-11-17-optimizely-supply-chain
event_id: brief-2026-11-17-optimizely-supply-chain
revision: 1
activity_at: "2026-11-17T20:54:45Z"
title: Optimizely Web Experimentation supply-chain compromise
slug: 2026-11-optimizely-supply-chain
description: An attacker exploited a vulnerability in Optimizely Web Experimentation to inject malicious JavaScript into 178 customer project snippets on November 16, 2026.
date: "2026-11-17T20:54:45Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.sophos.com/en-us/blog/hijacked-optimizely-snippets-served-malicious-code
  observed_at: "2026-11-16T00:00:00Z"
  confidence: high
source_assessment:
  reliability: A
  credibility: "1"
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Verified against Sophos X-Ops advisory.
tags:
  - supply-chain
  - web-application
  - js-injection
vendors:
  - Optimizely
products:
  - Web Experimentation
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: On November 17, 2026, Optimizely reported that an attacker exploited a vulnerability in its Web Experimentation product to add malicious JavaScript to some customer projects.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.007
    subtechnique_name: JavaScript
    evidence: Third-party reporting indicates that the code was injected into snippets belonging to 178 organizations, including CNN, the BBC, and Zoom, on November 16.
    confidence_band: high
references:
  - https://www.sophos.com/en-us/blog/hijacked-optimizely-snippets-served-malicious-code
action_plan:
  priority: immediate_escalation
  immediate_actions:
    - action: Check Optimizely Web Experimentation projects for code injected on November 16, 2026.
      due: immediate
      evidence: Organizations using Optimizely Web Experimentation should check their projects for code injected on November 16
  hunt_leads:
    - lead: Identify unauthorized modifications to external-facing JavaScript snippets or experiment configurations within the Optimizely platform dashboard or audit logs initiated on or around November 16, 2026.
      technique_id: T1190
      data_needed:
        - Optimizely Audit Logs
        - Change Management Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: On November 17, 2026, Optimizely reported that an attacker exploited a vulnerability in its Web Experimentation product to add malicious JavaScript to some customer projects.
    - lead: Perform a retrospective analysis of web traffic and Content Security Policy (CSP) violation reports to detect execution of unrecognized or unauthorized JavaScript snippets loaded from Optimizely-hosted resources on websites.
      technique_id: T1059
      data_needed:
        - Web Application Firewall logs
        - Content Security Policy (CSP) violation reports
        - Browser telemetry/client-side monitoring
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Third-party reporting indicates that the code was injected into snippets belonging to 178 organizations, including CNN, the BBC, and Zoom, on November 16.
---

## Overview
On November 17, 2026, Optimizely reported that an attacker exploited a vulnerability in its Web Experimentation product to add malicious JavaScript to some customer projects. Reports indicate that the code was injected into snippets belonging to 178 organizations, including CNN, the BBC, and Zoom, on November 16, 2026.

## Attack Chain
The attacker exploited a vulnerability within the Web Experimentation product to inject malicious JavaScript into customer-managed snippets, resulting in unauthorized code execution on the affected websites.

## Impact
The compromise resulted in malicious JavaScript being served to visitors of 178 impacted organizations.

## Recommendation
- Organizations using Optimizely Web Experimentation should check their projects for code injected on November 16, 2026.
- Organizations should monitor the Optimizely incident page to stay up to date on the latest recommendations.
