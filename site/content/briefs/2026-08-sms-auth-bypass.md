---
title: Authentication Bypass in IE-SR-2TX-WL-4G via SMS Retry Mechanism
slug: 2026-08-sms-auth-bypass
description: An authentication bypass vulnerability in IE-SR-2TX-WL-4G devices allows unauthenticated attackers to disable SMS password protection by triggering a fail-retry counter, leading to unauthorized command execution.
date: "2026-08-25T12:08:01Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - IE-SR
products:
  - IE-SR-2TX-WL-4G
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker who is able to send SMS messages to the device can deliberately trigger this by submitting 5 or more invalid passwords.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1562.001
    technique_name: 'Impair Defenses: Disable or Modify System Firewall'
    evidence: after 5 consecutive failed attempts, SMS password authorization is automatically disabled.
    confidence_band: high
cves:
  - id: CVE-2026-63587
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63587
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Review cellular gateway configurations to verify if password authorization is active
      owner: IT Operations
      due: 48h
      evidence: SMS control function... can require a password... via the 'Enable Password Authorization' setting.
  mitigation_plan:
    - priority: immediate
      action: Restrict SMS sender sources at the carrier level if possible
      owner: IT Operations
      addresses: CVE-2026-63587
      evidence: An unauthenticated remote attacker who is able to send SMS messages to the device can deliberately trigger this.
---

The IE-SR-2TX-WL-4G gateway contains a critical authentication vulnerability regarding its SMS control function. When the 'Enable Password Authorization' feature is active, the device tracks failed authentication attempts. A flaw in the design causes the device to automatically disable the requirement for a password after five consecutive failed attempts. An unauthenticated attacker capable of sending SMS messages to the device can exploit this by submitting five invalid password commands. Once the counter reaches the threshold, the device drops the authentication requirement for all subsequent SMS commands, granting the attacker the ability to tamper with configurations, leak device information, or cause a full denial of service. This vulnerability is significant as it provides remote, unauthenticated access to the gateway via the cellular network interface.

## Impact

Successful exploitation allows an unauthenticated remote attacker to gain administrative control over the affected device via SMS. Potential damage includes unauthorized configuration changes, exfiltration of device-specific information, and total loss of availability through disruptive command execution, impacting industrial or remote networking environments where these gateways are deployed.

## Recommendation

Prioritized actions for security teams:
- Verify if 'Enable Password Authorization' is currently enforced on all deployed IE-SR-2TX-WL-4G units.
- Review documentation for firmware updates from the vendor to address the retry counter logic.
- Implement cellular network-level SMS filtering to restrict the sender source for all managed gateways, preventing unauthorized remote access.
- Audit device configuration logs for recurring patterns of failed SMS password attempts which may indicate exploitation attempts.
