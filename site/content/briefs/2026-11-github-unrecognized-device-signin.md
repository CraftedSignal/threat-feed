---
brief_id: brief-2026-11-17-github-unrecognized-device-signin
event_id: brief-2026-11-17-github-unrecognized-device-signin
revision: 1
activity_at: "2026-11-17T14:58:40Z"
title: 'GitHub: Unrecognized device sign-in audit'
slug: 2026-11-github-unrecognized-device-signin
description: This detection identifies potential account takeover attempts targeting GitHub Enterprise Managed User (EMU) accounts by flagging authentication events from new devices or locations.
date: "2026-11-17T14:58:40Z"
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
  validation_status: Detection logic defined in source requires SIEM-specific implementation.
vendors:
  - GitHub
products:
  - GitHub Enterprise Managed User
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    subtechnique_id: T1078.004
    subtechnique_name: Cloud Accounts
    evidence: A sign-in from an unfamiliar device can indicate that stolen credentials or a hijacked session are being used from attacker infrastructure.
    confidence_band: high
references:
  - https://securitylabs.datadoghq.com/articles/mapping-out-your-unknown-threat-hunters-guide-to-github/
  - https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/reviewing-your-security-log
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/initial_access_github_unrecognized_device_signin.toml
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable ingestion of GitHub enterprise audit logs into the SIEM
      owner: SOC
      due: 48h
      evidence: The rule is intended for GitHub Enterprise Managed User (EMU) enterprises where user security-log actions stream into the enterprise audit log.
  hunt_leads:
    - lead: Hunt for user sign-in events associated with unrecognized device identifiers or novel IP locations in GitHub audit logs.
      technique_id: T1078.004
      data_needed:
        - GitHub audit log (event.action, github.actor_ip, github.device, github.user_agent)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This rule fires on GitHub's user.sign_in_from_unrecognized_device, user.sign_in_from_unrecognized_device_and_location, and user.new_device_used audit actions.
---

## Overview

GitHub emits specific audit actions when a user account authenticates from a device or location not previously associated with that account. In Enterprise Managed User (EMU) environments, these actions stream to the enterprise audit log, providing visibility into potential credential misuse or session hijacking. Monitoring for these events is critical for detecting early stages of account compromise, particularly when such sign-ins are followed by unauthorized persistence mechanism creation, such as new personal access tokens or SSH keys.

## Impact

Unauthorized access to GitHub accounts can lead to sensitive source code exposure, supply chain tampering, or the abuse of CI/CD pipelines. This detection is focused specifically on EMU enterprise audit data, as non-EMU personal accounts do not typically stream these security logs to external security information and event management (SIEM) platforms.

## Recommendation

- Deploy detection logic to monitor GitHub audit logs for `user.sign_in_from_unrecognized_device`, `user.sign_in_from_unrecognized_device_and_location`, and `user.new_device_used` events.
- Establish an incident response workflow to verify sign-in events with the associated user, checking device metadata and source IP geolocation.
- If a sign-in is identified as malicious, perform immediate password resets, revoke all active sessions, and rotate personal access tokens or SSH keys created during the suspicious session period.
