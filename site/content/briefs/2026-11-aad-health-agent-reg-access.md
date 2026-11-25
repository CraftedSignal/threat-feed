---
brief_id: brief-2026-11-25-aad-health-agent-reg-access
event_id: brief-2026-11-25-aad-health-agent-reg-access
revision: 1
activity_at: "2026-11-25T16:21:46Z"
title: Azure AD Health Monitoring Agent Registry Keys Access
slug: 2026-11-aad-health-agent-reg-access
description: This detection monitors for unauthorized access to the Azure AD Connect Health monitoring agent registry key, which may indicate suspicious activity.
date: "2026-11-25T16:21:46Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
tags:
  - attack.discovery
  - attack.t1012
products:
  - Azure AD Connect Health Monitoring Agent
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1012
    technique_name: Query Registry
    evidence: Detection uses Windows security events to detect suspicious access attempts to the registry key of Azure AD Health monitoring agent.
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_aadhealth_mon_agent_regkey_access.yml
  - https://aadinternals.com/post/hybridhealthagent/
  - https://github.com/OTRF/Set-AuditRule/blob/c3dec5443414231714d850565d364ca73475ade5/rules/registry/aad_connect_health_monitoring_agent.yml
rules:
  - title: Azure AD Health Monitoring Agent Registry Keys Access
    description: This detection uses Windows security events to detect suspicious access attempts to the registry key of Azure AD Health monitoring agent. This detection requires an access control entry (ACE) on the system access control list (SACL) of the following securable object HKLM\SOFTWARE\Microsoft\Microsoft Online\Reporting\MonitoringAgent.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1012
    data_sources:
      - registry_set
      - windows
      - security
rules_count: 1
---

## Overview

The Azure AD Connect Health monitoring agent registry key at HKLM\SOFTWARE\Microsoft\Microsoft Online\Reporting\MonitoringAgent is a target for unauthorized access. This detection uses Windows security events to identify suspicious access attempts.

## Attack Chain

This activity is categorized as Registry Discovery (T1012), where an adversary may interact with sensitive configuration registry keys.

## Impact

Unauthorized access to this key could facilitate the discovery of configuration settings or sensitive information regarding the hybrid health monitoring agent.

## Recommendation

This detection requires an access control entry (ACE) on the system access control list (SACL) of the following securable object: HKLM\SOFTWARE\Microsoft\Microsoft Online\Reporting\MonitoringAgent.
