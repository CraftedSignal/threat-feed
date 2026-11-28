---
brief_id: brief-2026-11-28-microsoft-intune-bulk-wipe
event_id: brief-2026-11-28-microsoft-intune-bulk-wipe
revision: 1
activity_at: "2026-11-28T20:51:29Z"
title: 'Microsoft Intune: Bulk device wipe detection'
slug: 2026-11-microsoft-intune-bulk-wipe
description: This detection monitors for a high volume of 'wipe ManagedDevice' operations in Microsoft Intune, which may indicate a large-scale unauthorized factory reset attack against managed endpoints.
date: "2026-11-28T20:51:29Z"
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
  likelihood: likely
tags:
  - cloud
  - azure
  - intune
  - data-wiping
vendors:
  - Microsoft
products:
  - Intune
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1561.001
    technique_name: Disk Content Wipe
    evidence: If confirmed malicious, an attacker can abuse this action to perform a large-scale data wiping attack against your managed endpoints.
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/microsoft_intune_bulk_wipe.yml
  - https://www.lumos.com/blog/stryker-hack
  - https://www.covertswarm.com/post/swarm-intelligence-strykers-intune-wipe-proves-your-bcdr-plan-has-a-single-point-of-failure
  - https://www.wwt.com/blog/how-the-stryker-intune-wipe-incident-highlights-a-critical-gap-in-endpoint-control
rules:
  - title: Microsoft Intune Bulk Wipe
    description: Detects 5+ 'wipe ManagedDevice' events per hour by a single user using Azure Monitor Activity logs.
    platform: sigma
    severity: medium
    data_sources:
      - cloud
      - Intune
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Splunk detection rule to identify anomalous Intune wipe operations
      owner: Detection Engineering
  mitigation_plan:
    - action: Configure Azure EventHub to ingest Intune audit logs via Diagnostic settings as documented.
      addresses: Missing audit visibility for Intune wipe actions
      evidence: To configure this logging, visit Intune > Tenant administration > Diagnostic settings > Add diagnostic settings & send events to the activity audit event hub.
---

## Overview
The Microsoft Intune Bulk Wipe detection analytic identifies a high volume of 'wipe ManagedDevice' events originating from the Intune admin portal. By default, the detection triggers when a user initiates five or more wipe requests within a one-hour period using Azure Monitor Activity logs.

## Attack Chain
The 'wipe ManagedDevice' action initiates a factory reset on Intune-enrolled endpoints. An attacker with sufficient permissions can abuse this function to perform a large-scale data wiping attack against managed assets.

## Impact
Successful abuse of this action results in the remote factory reset of endpoints, leading to significant data loss and operational disruption.

## Recommendation
To implement this detection, ensure the Splunk Add-on for Microsoft Cloud Services is configured to ingest Intune audit logs via Azure EventHub. Configuration requires navigating to Intune > Tenant administration > Diagnostic settings > Add diagnostic settings, and directing events to the activity audit event hub. The threshold should be adjusted based on the organization's baseline for legitimate administrative activity, such as device offboarding or theft response.
