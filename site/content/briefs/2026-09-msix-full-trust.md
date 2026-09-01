---
title: Detection of MSIX Full Trust Package Installation
slug: 2026-09-msix-full-trust
description: Detection of MSIX/AppX package installations requesting full trust capabilities which circumvent standard application container isolation and operate with elevated privileges.
date: "2026-09-01T12:16:43Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - execution
  - persistence
  - defense-impairment
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: The installation of MSIX/AppX packages with the full trust capability allows applications to run with the user's privilege level.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Controls
    evidence: Full trust allows applications to circumvent standard application container restrictions.
    confidence_band: med
references:
  - https://www.splunk.com/en_us/blog/security/msix-weaponization-threat-detection-splunk.html
rules:
  - title: Detect Suspicious Full Trust MSIX Package Installation
    description: Detects the installation of MSIX/AppX packages with full trust privileges which run with elevated privileges outside normal AppX container restrictions
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
      - execution
    techniques:
      - T1204.002
      - T1553.005
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to monitor Event ID 400
      owner: Detection Engineering
      due: 72h
      evidence: Source provides logic for identifying full-trust package installations
  mitigation_plan:
    - priority: medium_term
      action: Restrict MSIX/AppX deployment sources to approved corporate signed repositories
      owner: IT Operations
      addresses: Technique T1553.005
---

The installation of MSIX or AppX packages with the "full trust" capability allows applications to run with the user's privilege level outside of the standard AppX container restrictions. This capability is often exploited by adversaries to achieve persistence and execute code with elevated rights while bypassing sandbox controls. The AppX Deployment Server (AppxDeployment-Server) logs provide visibility into these installations, specifically via Event ID 400. Defenders must baseline legitimate software deployment pipelines to differentiate between authorized enterprise application updates and malicious package delivery. This detection logic focuses on flagging installations that do not originate from trusted Microsoft-signed update sources or standard application installation directories.

## Impact

Successful installation of a malicious full-trust package results in privilege escalation or persistent execution within the user context, as the application is no longer bound by containerized security policies. This technique allows attackers to maintain stealthy presence and interact directly with the local file system and registry, potentially facilitating lateral movement or further malware deployment.

## Recommendation

Deploy the Sigma rule below to monitor for suspicious full-trust package installations. Before enabling alerts in production, baseline the environment to identify legitimate internal tools or management software that may trigger this rule. Add verified internal software paths or specific signer information to the exclusion filters to reduce noise. Ensure that the AppX Deployment Server event logs are being ingested into your SIEM platform.
