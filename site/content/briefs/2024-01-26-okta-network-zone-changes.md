---
title: Okta Network Zone Deactivation or Deletion
slug: 2024-01-26-okta-network-zone-changes
description: An Okta network zone was deactivated or deleted, potentially indicating malicious activity aimed at bypassing security controls.
date: "2024-01-26T18:22:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - okta
  - network-zone
  - impact
vendors:
  - Okta
products:
  - Okta Identity Engine
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://developer.okta.com/docs/reference/api/system-log/
  - https://developer.okta.com/docs/reference/api/event-types/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_network_zone_deactivated_or_deleted.yml
rules:
  - title: Okta Network Zone Deactivated or Deleted
    description: Detects when an Okta Network Zone is Deactivated or Deleted.
    platform: sigma
    severity: medium
    tactics:
      - impact
    data_sources:
      - okta
      - okta
  - title: Okta Admin Activity - Network Zone Deletion
    description: Detects when an Okta Network Zone is deleted by an admin user.
    platform: sigma
    severity: medium
    tactics:
      - impact
    data_sources:
      - okta
      - okta
rules_count: 2
---

Okta network zones define trusted network boundaries for user access. These zones are configured with specific IP address ranges and can be used to restrict access to applications and resources. When an Okta network zone is deactivated or deleted, it can indicate a malicious actor attempting to weaken security policies, potentially allowing unauthorized access from untrusted locations. This activity is relevant for defenders because it may signal a breach in progress or preparation for future attacks. Compromised administrator accounts are often used to make unauthorized configuration changes in SaaS platforms. This alert focuses on activity within the Okta platform itself.

## Attack Chain

1. An attacker gains unauthorized access to an Okta administrator account, potentially through credential theft or phishing.
2. The attacker authenticates to the Okta administrative console.
3. The attacker navigates to the network zone configuration within the Okta admin console.
4. The attacker identifies a target network zone that restricts access to critical resources.
5. The attacker deactivates the target network zone, effectively disabling its restrictions. Alternatively, the attacker deletes the network zone.
6. The attacker may modify other security settings, such as MFA policies, to further weaken the security posture.
7. The attacker leverages the relaxed network restrictions to access sensitive applications or data from previously unauthorized locations.
8. The attacker performs malicious actions, such as data exfiltration or lateral movement, using the compromised Okta session.

## Impact

The deactivation or deletion of an Okta network zone can have serious consequences. It can lead to unauthorized access to sensitive applications and data, potentially resulting in data breaches, financial loss, and reputational damage. The impact is especially high if the affected network zone was protecting critical infrastructure or sensitive customer data. Depending on the scope of access granted, a single deactivated zone could expose data belonging to thousands of users.

## Recommendation

*   Deploy the "Okta Network Zone Deactivated or Deleted" Sigma rule to your SIEM to detect this activity (logsource: okta, service: okta, eventType: zone.deactivate/zone.delete).
*   Investigate any detected instances of network zone deactivation or deletion to determine if they were authorized changes.
*   Review Okta administrator account activity for signs of compromise, such as login attempts from unusual locations.
*   Enforce multi-factor authentication (MFA) for all Okta administrator accounts to prevent unauthorized access.
*   Monitor the Okta system logs for other suspicious configuration changes, such as modifications to MFA policies or application assignments.
