---
brief_id: brief-2026-11-16-non-browser-browser-cache-access
event_id: brief-2026-11-16-non-browser-browser-cache-access
revision: 1
activity_at: "2026-11-16T04:19:54Z"
title: Unauthorized Non-Browser Process Access to Browser Cache Directories
slug: 2026-11-non-browser-browser-cache-access
description: This detection monitors for non-browser processes accessing local web browser cache files, a technique often associated with 'Browser Cache Smuggling' to stage payloads or exfiltrate sensitive web-delivered content.
date: "2026-11-16T04:19:54Z"
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
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Detection logic defined based on provided Splunk ES analytic; requires environment-specific SACL configuration for telemetry generation.
tags:
  - collection
  - command-and-control
  - defense-evasion
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: A script or utility reading Firefox, Chrome, Edge, Brave, or Chromium cache entries may be extracting web-delivered content for staging or execution.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: A script or utility reading Firefox, Chrome, Edge, Brave, or Chromium cache entries may be extracting web-delivered content for staging or execution.
    confidence_band: med
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027.006
    technique_name: HTML Smuggling
    evidence: A script or utility reading Firefox, Chrome, Edge, Brave, or Chromium cache entries may be extracting web-delivered content for staging or execution.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_non_browser_process_access_browser_cache_dir.yml
  - https://attack.mitre.org/techniques/T1005/
  - https://attack.mitre.org/techniques/T1105/
  - https://attack.mitre.org/techniques/T1027/006/
  - https://sensepost.com/blog/2023/browsers-cache-smuggling/
rules:
  - title: Detect Non-Browser Process Access to Browser Cache
    description: Detects non-browser processes accessing files within browser cache directories using Windows Event ID 4663, which may indicate payload staging or data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1005
      - T1027.006
      - T1105
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable Audit Object Access in Windows GPO and configure SACLs on browser cache directories.
      owner: IT Operations
      due: 48h
      evidence: Successful implementation of this search requires Event Code 4663 and SACL configuration.
    - action: Deploy the non-browser cache access detection rule to identify anomalous process interactions.
      owner: Detection Engineering
      due: 24h
      evidence: This analytic detects non-browser processes accessing files in local browser cache directories.
  hunt_leads:
    - lead: Identify non-browser processes accessing directories containing 'Cache_Data' or 'cache2/entries'.
      technique_id: T1005
      data_needed:
        - Windows Event ID 4663
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: A script or utility reading Firefox, Chrome, Edge, Brave, or Chromium cache entries may be extracting web-delivered content for staging or execution.
---

## Overview

Malicious actors may target local browser cache directories to extract web-delivered content, staging materials, or sensitive data. This activity, known as 'Browser Cache Smuggling', involves reading cache entries from major browsers including Firefox, Chrome, Edge, Brave, and Chromium. By leveraging Windows Security Event ID 4663, detection engineers can identify unauthorized processes that attempt to access these directories.

## Impact

If successful, an attacker can covertly stage malicious payloads directly from legitimate browser-downloaded content or exfiltrate cached web data, bypassing traditional network-based egress filtering by masquerading as browser activity.

## Recommendation

To detect this behavior, prioritize the following actions:
- Enable Windows 'Audit Object Access' in Group Policy, ensuring both 'Success' and 'Failure' are tracked for object access.
- Configure System Access Control Lists (SACL) on the specific browser cache directory paths listed in the detection criteria.
- Deploy the provided detection logic to flag non-browser processes accessing these directories.
- Review identified anomalies for legitimate backup, forensic, or security tooling to reduce false positives.
