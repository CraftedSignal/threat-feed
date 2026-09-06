---
title: Abuse of osascript for Deceptive UI Prompts on macOS
slug: 2026-09-macos-osascript-spoofing
description: Adversaries are abusing the macOS osascript utility to present deceptive security-themed dialog boxes to trick users into disclosing credentials.
date: "2026-09-06T22:41:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Adversaries may abuse osascript to present fake system messages or credential prompts and trick users into disclosing sensitive information.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1056
    technique_name: Input Capture
    evidence: Adversaries may abuse osascript to present fake system messages or credential prompts and trick users into disclosing sensitive information.
    confidence_band: high
rules:
  - title: Detect Suspicious macOS osascript UI Prompts
    description: Detects the execution of osascript with arguments indicating deceptive dialog or alert prompts aimed at credential theft
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - execution
    techniques:
      - T1056.002
      - T1059.002
    data_sources:
      - process_creation
      - macos
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to monitor for suspicious osascript UI activity
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific command line patterns for osascript abuse
  hunt_leads:
    - lead: Search endpoint logs for historical osascript executions containing password or authentication keywords
      technique_id: T1056.002
      data_needed:
        - process_creation
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The technique is known to be used by infostealers and should be audited.
---

Adversaries are leveraging the native macOS osascript utility to conduct social engineering campaigns by displaying fake system alerts and credential-harvesting dialogs. By executing AppleScript commands through osascript, attackers can create professional-looking pop-up windows that mimic legitimate macOS system messages or security update notifications. These prompts use deceptive keywords such as "authentication," "security update," "system error," and "password" to create a sense of urgency, pressuring the user to enter sensitive information or credentials. This technique is a documented method for credential theft and potential privilege escalation, as users may be tricked into performing actions that grant the attacker unauthorized access or elevated permissions. Defenders should monitor for suspicious command-line arguments passed to osascript that match these UI-centric patterns.

## Impact

The abuse of osascript for deceptive prompts allows adversaries to bypass traditional defenses by manipulating the end-user rather than exploiting software vulnerabilities. If successful, this can lead to the harvesting of plaintext credentials, unauthorized MFA tokens, or user-approved execution of malicious payloads, potentially resulting in full compromise of the local macOS endpoint.

## Recommendation

- Deploy process-level monitoring on macOS endpoints to capture the full command line of all osascript executions.
- Implement the detection rule below in your SIEM to flag suspicious osascript command arguments.
- Review the parent process and the identity of the user executing osascript to differentiate between malicious social engineering and legitimate administrative or MDM-driven alerts.
- Integrate osquery telemetry with the organization's security data models to provide consistent visibility into process-creation events across macOS assets.
