---
title: Detection of Malicious Outlook WebView Registry Manipulation
slug: 2026-10-outlook-webview-reg-mod
description: Attackers may modify Outlook registry keys related to WebView and Today features to redirect web-based components to malicious URLs, facilitating phishing and credential theft.
date: "2026-10-12T18:17:29Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - registry
  - outlook
vendors:
  - Microsoft
products:
  - Outlook
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: The following analytic identifies modifications to specific Outlook registry values related to WebView and Today features.
    confidence_band: high
rules:
  - title: Detect Outlook WebView Registry Modification
    description: Detects modifications to Outlook WebView and Today registry keys where the URL value is updated, potentially indicating malicious redirection.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
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
    - action: Deploy registry modification detection rule
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic logic for Outlook registry monitoring.
  hunt_leads:
    - lead: Look for historical registry modifications to Outlook WebView paths
      technique_id: T1112
      data_needed:
        - Registry modification logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: This technique could lead to phishing attempts or data theft.
---

This threat involves the unauthorized modification of specific registry keys within the Microsoft Outlook configuration that govern the behavior of the "WebView" and "Today" features. By altering the "URL" value within these registry paths, an attacker can influence the web-based content rendered by the Outlook email client. This manipulation is a known technique for redirecting users to attacker-controlled sites, which can lead to sophisticated phishing campaigns, session hijacking, or credential harvesting. Because these features are frequently used for internal enterprise portals or dashboard displays within the Outlook interface, users may be more susceptible to trust malicious content presented through these hijacked components. Defenders should monitor registry modifications targeting these specific paths to identify attempts to persist or pivot through the Outlook client environment.

## Attack Chain

1. Attacker gains initial access or code execution on the target workstation.
2. Attacker enumerates the registry to identify current Microsoft Office/Outlook configuration paths.
3. Attacker identifies the WebView or Today registry keys located under HKCU or HKLM Software\Microsoft\Office.
4. Attacker modifies the "URL" value within the targeted registry path to point to a malicious remote server.
5. The Outlook client initializes or refreshes the WebView/Today component.
6. Outlook loads the attacker-specified URL, executing script or displaying fraudulent content to the user.
7. Attacker successfully performs phishing, data exfiltration, or secondary exploit delivery via the rendered web content.

## Impact

Successful exploitation allows for the compromise of the user's email client environment. This can result in the loss of sensitive corporate credentials, unauthorized access to internal web applications rendered within Outlook, and the potential for further endpoint compromise through the execution of malicious scripts within the WebView context.

## Recommendation

* Deploy the Sigma rule below to monitor registry modifications targeting Outlook WebView and Today registry paths.
* Configure Sysmon or EDR to capture Registry Event ID 13 and ensure registry path and value name fields are logged.
* Investigate any process modifying these registry keys that does not correspond to a standard Office update or administrative deployment tool.
