---
title: Potential Persistence via Event Viewer Registry Redirection
slug: 2026-09-event-viewer-persistence
description: An adversary can achieve persistence or defense impairment by modifying Windows registry keys to redirect Event Viewer's 'Events.asp' link handling to a malicious binary or command line.
date: "2026-09-01T12:12:55Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - defense-impairment
  - windows
  - registry
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1112
    technique_name: Modify Registry
    evidence: The registry keys can be abused to establish persistence by redirecting Event Viewer requests.
    confidence_band: high
rules:
  - title: Detect Potential Persistence Via Event Viewer Registry Modification
    description: Detects modifications to Event Viewer redirection registry keys that do not match default Windows configurations.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
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
    - action: Deploy Sigma rule to monitor registry keys
      owner: Detection Engineering
      due: 24h
      evidence: Standard detection practice for T1112
  mitigation_plan:
    - priority: medium_term
      action: Audit all endpoints for non-standard values in the identified registry paths
      owner: IT Operations
      addresses: T1112
---

This technique leverages the Event Viewer's built-in functionality that allows redirection of event-related links, historically used for 'Events.asp' content. By modifying specific registry keys under 'Microsoft\Windows NT\CurrentVersion\Event Viewer', an attacker can specify a custom 'MicrosoftRedirectionProgram' or 'MicrosoftRedirectionURL'. When a user triggers an event link in Event Viewer, the system executes the attacker-defined program or command line parameters instead of the legitimate Microsoft-provided URL. This mechanism can be abused to achieve persistence, execute arbitrary code, or redirect users to malicious landing pages. Because Event Viewer may run under higher integrity levels or be accessed by administrative users, this modification can be a potent method for maintaining stealthy access or performing defense impairment. Defenders should monitor registry modifications to these specific Event Viewer paths that deviate from known-good baseline configurations provided by Group Policy.

## Attack Chain

1. Attacker gains initial access to the Windows endpoint via secondary vector (e.g., phishing, exploit).
2. Attacker performs local reconnaissance to identify current Event Viewer configuration.
3. Attacker modifies the registry key 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Event Viewer\MicrosoftRedirectionProgram' to point to a malicious binary.
4. Attacker optionally modifies 'MicrosoftRedirectionURL' or 'MicrosoftRedirectionProgramCommandLineParameters' to pass malicious arguments.
5. Attacker waits for the user or an automated process to open Event Viewer and interact with an event link.
6. The system executes the attacker's binary under the context of the Event Viewer session.
7. Final objective is achieved, such as persistence, privilege escalation, or command execution.

## Impact

Successful exploitation allows for arbitrary code execution with the permissions of the user interacting with the Event Viewer. This can lead to system-wide persistence, lateral movement, or unauthorized exfiltration of data depending on the payload executed.

## Recommendation

1. Deploy the provided Sigma rule to monitor registry modifications in the 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Event Viewer\' path.
2. Implement an allowlist for the 'MicrosoftRedirectionProgram' value to ensure only legitimate HelpCtr.exe or authorized support binaries are defined.
3. Review existing Group Policy configurations to confirm that Event Viewer links are correctly pointed to trusted endpoints.
