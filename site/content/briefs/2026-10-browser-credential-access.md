---
title: Detection of Unauthorized Process Access to Browser Credential Stores
slug: 2026-10-browser-credential-access
description: Detection of anomalous processes accessing browser user data directories indicates potential credential theft attempts by various information stealers.
date: "2026-10-05T18:01:54Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - information-stealer
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1012
    technique_name: Query Registry
    evidence: This tactic/technique has been observed in various Trojan Stealers, such as SnakeKeylogger, which attempt to gather sensitive browser information.
    confidence_band: high
rules:
  - title: Detect Unauthorized Access to Browser Data Profiles
    description: Detects non-browser processes accessing browser user data folders, which is indicative of credential theft activity.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1012
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
    - action: Enable Audit Object Access for browser profile directories
      owner: IT Operations
      due: 72h
      evidence: Source requirement for Event 4663
  hunt_leads:
    - lead: Search for processes identified by Event 4663 accessing User Data folders
      technique_id: T1012
      data_needed:
        - Windows Security Event 4663
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Search pattern provided in source
---

This detection analytic identifies non-standard processes attempting to access sensitive browser user data directories on Windows systems. Threat actors frequently leverage this technique to exfiltrate saved credentials, cookies, and personal information as part of a broader credential theft or reconnaissance strategy. This behavior has been observed across numerous malware families, including SnakeKeylogger, StealC, and others documented in various intelligence reports. The detection relies on Windows Security Event ID 4663, which audits object access. By comparing the process requesting access to a curated list of authorized browsers, defenders can isolate malicious or suspicious activity that deviates from established baseline browser behavior. 

## Impact

Successful exfiltration of browser data provides attackers with immediate access to cached credentials for banking, corporate, and personal services, facilitating unauthorized account takeover, lateral movement, and long-term persistent access to the target environment.

## Recommendation

1. Enable "Audit Object Access" in Group Policy for the targeted directories to generate Event ID 4663 logs.
2. Maintain a baseline list of authorized browser applications and their paths to minimize false positives in your environment.
3. Deploy the provided Sigma rule to alert on non-browser processes attempting to read sensitive browser data files.
4. Investigate any process flagged by the detection, focusing on the parent process lineage and potential network activity immediately following the access request.
