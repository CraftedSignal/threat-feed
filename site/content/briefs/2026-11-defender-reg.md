---
brief_id: brief-2026-11-16-defender-reg
event_id: brief-2026-11-16-defender-reg
revision: 1
activity_at: "2026-11-16T04:21:05Z"
title: 'Windows Defender: Antivirus protection disabled via registry modification'
slug: 2026-11-defender-reg
description: Adversaries modify Windows Defender registry settings to disable antivirus and antispyware protections to evade detection and maintain persistence on compromised systems.
date: "2026-11-16T04:21:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
vendors:
  - Microsoft
products:
  - Windows Defender
affected_os:
  - Windows
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/disable_defender_antivirus_registry.yml
  - https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
rules:
  - title: Disable Defender AntiVirus Registry
    description: Detects the modification of Windows Defender registry settings (DisableAntiSpyware or DisableAntiVirus) to 1, which effectively disables antivirus and antispyware protections.
    platform: sigma
    severity: medium
    data_sources:
      - registry_set
      - windows
rules_count: 1
---

## Overview
The following analytic detects the modification of Windows Defender registry settings to disable antivirus and antispyware protections. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to registry paths associated with Windows Defender policies.

## Attack Chain
Adversaries modify specific Windows registry keys (DisableAntiSpyware or DisableAntiVirus) to disable security protections. This is a common tactic used by adversaries to evade detection and maintain persistence on compromised systems.

## Impact
If confirmed malicious, this action could allow attackers to execute further malicious activities undetected, leading to potential data breaches, system compromise, and further propagation of malware within the network.

## Recommendation
To successfully implement this search, you need to be ingesting logs with the registry value name, registry path, and registry value data from your endpoints. If using Sysmon, version 2.0 or higher of the official Sysmon TA is required.
