---
title: Google Workspace 2SV Policy Disabled
slug: 2024-01-google-workspace-2sv-disabled
description: An adversary may disable 2-Step Verification (2SV) in Google Workspace to weaken account security and facilitate unauthorized access.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - google-workspace
  - 2sv
  - persistence
vendors:
  - Google
products:
  - Google Workspace
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1556
    technique_name: Modify Authentication Process
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/google_workspace/persistence_google_workspace_2sv_policy_disabled.toml
  - https://support.google.com/a/answer/9176657?hl=en
  - https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one
  - https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two
rules:
  - title: Google Workspace 2SV Disabled via Activity Events
    description: Detects when a Google Workspace 2SV policy is disabled via activity events.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1556
    data_sources:
      - webserver
      - linux
  - title: Google Workspace 2SV Policy Disabled - Admin Console
    description: Detects when a Google Workspace 2SV policy is disabled through the admin console based on event logs.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1556
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Google Workspace administrators can enforce 2-Step Verification (2SV) to enhance user account security, requiring users to verify their identity beyond simple login credentials. This policy can be configured with various verification methods and enrollment periods. However, a malicious actor with administrative privileges may disable 2SV policies to reduce the security requirements for accessing targeted accounts. This could be a precursor to credential access or data exfiltration. The Elastic detection rule "Google Workspace 2SV Policy Disabled" was released on 2022-08-26 and updated on 2026-04-10 to detect this activity. This activity is important for defenders because it can lead to unauthorized access to sensitive data and systems.

## Attack Chain

1. An attacker gains unauthorized access to a Google Workspace administrator account, possibly through credential compromise or phishing.
2. The attacker authenticates to the Google Workspace admin console using the compromised credentials.
3. The attacker navigates to the Security settings within the admin console.
4. The attacker locates the 2-Step Verification settings.
5. The attacker disables the 2SV enforcement policy for specific organizational units or the entire domain. This generates a `google_workspace.login` event with `event.action: "2sv_disable"`.
6. The attacker may then attempt to access user accounts without the 2SV requirement, potentially using previously obtained credentials.
7. Upon successful login, the attacker performs malicious actions such as accessing sensitive data, modifying configurations, or establishing persistence.
8. The attacker covers their tracks by deleting audit logs or creating new admin accounts with modified permissions.

## Impact

Disabling 2SV weakens the overall security posture of a Google Workspace environment. If successful, attackers can gain unauthorized access to user accounts, leading to data breaches, financial losses, and reputational damage. The number of affected users depends on the scope of the 2SV policy change and the extent of the attacker's access. Organizations in any sector relying on Google Workspace for email, file storage, or other services are vulnerable.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect instances of 2SV policy being disabled and tune for your environment.
*   Review Google Workspace audit logs (`filebeat-*`, `logs-google_workspace*`) for unexpected 2SV configuration changes.
*   Implement the security best practices outlined by Google: https://support.google.com/a/answer/7587183
*   Monitor `user.name` or `source.user.email` in the alert and filter `event.dataset` for `google_workspace.login` and aggregate by `user.name`, `event.action` to identify impacted users and authentication events.
*   Reduce the `var.interval` in the Google Workspace Filebeat module to 10 minutes (10m) to decrease the risk of missed events.
