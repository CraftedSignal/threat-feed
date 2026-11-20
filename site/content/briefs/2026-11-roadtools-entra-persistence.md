---
brief_id: brief-2026-11-17-roadtools-entra-persistence
event_id: brief-2026-11-17-roadtools-entra-persistence
revision: 2
activity_at: "2026-11-20T15:40:52Z"
revision_history:
  - revision: 2
    at: "2026-11-20T15:40:52Z"
    checksum: sha256:3fe02456fdf36a8b4a048b7bb40494df5fee09fd4df146f1271684b9407b97bb
    summary: 'added detection rule: Entra ID Password Reset of Another User'
    changed_fields:
      - affected_os
      - lastmod
      - references
      - rules
      - tags
      - ttps
      - updates
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/persistence_entra_password_reset_of_another_user.toml
title: 'Microsoft Entra ID: Rogue device registration via ROADtools'
slug: 2026-11-roadtools-entra-persistence
description: Attackers leverage the ROADtools framework to register rogue devices in Microsoft Entra ID by spoofing specific default OS builds and naming patterns to acquire Primary Refresh Tokens and establish persistent access.
date: "2026-11-17T20:56:36Z"
lastmod: "2026-11-20T15:40:25Z"
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
tags:
  - persistence
  - cloud
  - identity
  - 'Domain: Cloud'
  - 'Data Source: Azure'
  - 'Data Source: Microsoft Entra ID Audit Logs'
  - 'Domain: Identity'
  - 'Platform: Azure'
  - 'Platform: Microsoft Entra ID'
  - 'Tactic: Persistence'
  - 'Rule Type: ES|QL'
vendors:
  - Microsoft
products:
  - Microsoft Entra ID
affected_os:
  - Cloud
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    subtechnique_id: T1098.005
    subtechnique_name: Device Registration
    evidence: Adversaries register rogue devices in Entra ID to acquire a Primary Refresh Token (PRT), establish persistence, and obtain trusted, programmatic access to the tenant.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Adversaries and business email compromise operators reset another user's password to hijack the account or establish persistence.
    confidence_band: high
references:
  - https://unit42.paloaltonetworks.com/roadtools-cloud-attacks/
  - https://github.com/dirkjanm/ROADtools
  - https://dirkjanm.io/introducing-roadtools-token-exchange-roadtx/
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/persistence_entra_id_roadtools_default_device_registration.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/persistence_entra_id_register_device_unusual_user_agent.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/persistence_entra_password_reset_of_another_user.toml
  - https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098.003/T1098.003.md
rules:
  - title: Entra ID Device Registration with ROADtools Default OS Build
    description: Detects Microsoft Entra ID device registrations using ROADtools default cloud device OS build values or hardcoded Windows Hello for Business user agents.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1098.005
    data_sources:
      - webserver
  - title: Entra ID Password Reset of Another User
    description: Identifies an Entra ID administrative password reset where the initiating principal differs from the target user, excluding activity by the Microsoft password reset service.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098
    data_sources:
      - azure.auditlogs
      - microsoft_entra_id
rules_count: 2
action_plan:
  priority: elevated
  owners:
    - SOC
    - Identity Team
  immediate_actions:
    - action: Deploy the provided detection rule for Entra ID audit logs to monitor for ROADtools-specific device registration characteristics.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific hardcoded values for OS version, host naming, and user agent strings used by ROADtools.
  hunt_leads:
    - lead: Investigate sign-in logs (azure.signinlogs) for tokens classified as primaryRefreshToken originating from recently registered devices.
      technique_id: T1098.005
      data_needed:
        - azure.signinlogs
        - azure.correlation_id
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: ROADtools registration is a precursor to PRT acquisition and persistent token-based access.
updates:
  - at: "2026-11-20T15:40:25Z"
    level: L1
    summary: 'added detection rule: Entra ID Password Reset of Another User'
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/persistence_entra_password_reset_of_another_user.toml
---

## Overview

The ROADtools (roadtx) framework facilitates persistence in Microsoft Entra ID environments by registering rogue devices that appear to be legitimate endpoints. Attackers utilize hardcoded default characteristics, specifically the cloud device OS build "10.0.19041.928" and device display names following the "DESKTOP-" pattern, to bypass security controls. Additionally, ROADtools can register devices via Windows Hello for Business using the hardcoded user-agent string "Dsreg/10.0 (Windows 10.0.19044.1826)". Successful registration allows attackers to acquire a Primary Refresh Token (PRT), bypass MFA and Conditional Access policies, and gain trusted, programmatic access to the tenant.

## Impact

- Acquisition of Primary Refresh Tokens (PRT) for persistent, authenticated access.
- Bypass of multi-factor authentication (MFA) and Conditional Access policies.
- Unauthorized programmatic access to sensitive tenant resources.

## Recommendation

- Monitor Microsoft Entra ID audit logs for the specific OS build and naming patterns identified by Elastic.
- Review device registration workflows to ensure all new device entries correlate with expected provisioning programs.
- Investigate sign-in logs for follow-on access using Primary Refresh Tokens immediately following suspicious device registrations.
- Implement Conditional Access policies to restrict device registration permissions and require MFA for all device join operations.
- Validate that device registration service actions are only initiated by authorized identities and from expected source IP ranges.
