---
title: Outlook WebView Registry Modification for Persistence
slug: 2026-09-outlook-homepage-persistence
description: Adversaries can achieve persistence and code execution by modifying the Outlook WebView registry keys to point to a malicious URL.
date: "2026-09-01T12:13:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - outlook
  - registry
  - windows
vendors:
  - Microsoft
products:
  - Outlook
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1112
    technique_name: Modify Registry
    evidence: An attacker can set a home page to achieve code execution and persistence by editing the WebView registry keys.
    confidence_band: high
rules:
  - title: Detect Outlook WebView Registry Persistence Modification
    description: Detects potential persistence activity via Outlook home page by monitoring modifications to WebView registry keys.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1112
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to the SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific registry paths for monitoring.
  hunt_leads:
    - lead: Search for existing registry keys containing URLs in the Outlook WebView path
      technique_id: T1112
      data_needed:
        - Registry configuration data
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Adversaries modify these keys to point to malicious URLs.
---

This threat involves the abuse of the Outlook Home Page feature, which allows users to display a web page within an Outlook folder. By modifying specific registry keys associated with Outlook WebView settings, an attacker can force Outlook to load an arbitrary URL upon startup or when a specific folder is accessed. This technique serves as a persistence mechanism and a potential vector for code execution, as the displayed page executes within the context of the Outlook process. While this functionality was designed to support folder-specific home pages, its exploitation provides an effective method for maintaining presence on a compromised system without requiring highly privileged modifications. Defenders should monitor registry modifications targeting Outlook configuration paths.

## Attack Chain

1. The attacker gains initial access to the target host through an unrelated vector.
2. The attacker identifies the Outlook configuration registry hive for the current user.
3. The attacker creates or modifies registry keys under `HKCU\Software\Microsoft\Office\<version>\Outlook\WebView\`.
4. The attacker sets the `URL` registry value to point to a malicious web resource or local file.
5. The Outlook application process (`outlook.exe`) is launched or restarted by the user or system.
6. The application reads the modified registry value to configure the WebView component.
7. The WebView component navigates to the attacker-supplied URL, executing the malicious content within the Outlook process context.

## Impact

Successful exploitation allows for persistent code execution within the security context of the Outlook process, potentially facilitating further malicious activities, data exfiltration, or lateral movement.

## Recommendation

1. Deploy the provided Sigma rule to monitor for registry modifications targeting Outlook WebView configuration paths.
2. Establish baselines for registry keys under `HKCU\Software\Microsoft\Office\*\Outlook\WebView\` to distinguish between legitimate enterprise configuration and unauthorized modifications.
3. Restrict user ability to modify Outlook registry configuration via Group Policy where applicable.
