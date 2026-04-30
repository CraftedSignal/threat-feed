---
title: Bitbucket Audit Log Configuration Modified
slug: 2024-10-bitbucket-audit-config-mod
description: An attacker may modify the Bitbucket audit log configuration to impair security monitoring and evade detection.
date: "2024-10-26T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - attack.defense-impairment
  - attack.t1562.004
  - bitbucket
vendors:
  - Atlassian
products:
  - Bitbucket
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://confluence.atlassian.com/bitbucketserver/view-and-configure-the-audit-log-776640417.html
  - https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_log_configuration_update_detected.yml
rules:
  - title: Bitbucket Audit Log Configuration Updated
    description: Detects changes to the Bitbucket audit log configuration.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
    techniques:
      - T1562.004
    data_sources:
      - bitbucket
      - audit
  - title: Bitbucket Audit Log Disabled
    description: Detects when Bitbucket audit logging is disabled.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
    techniques:
      - T1562.004
    data_sources:
      - bitbucket
      - audit
rules_count: 2
---

Attackers may target Bitbucket audit log configurations to reduce or eliminate logging, thereby hindering incident response and forensic investigations. Modifying audit settings is a defense evasion technique that allows malicious actors to operate with less visibility. This activity typically occurs post-compromise. This brief focuses on detecting such modifications. Visibility of audit events requires at least "Basic" log level configuration.

## Attack Chain

1. An attacker gains unauthorized access to a Bitbucket instance, potentially through compromised credentials or exploiting a vulnerability.
2. The attacker authenticates to the Bitbucket web interface or uses the Bitbucket API.
3. The attacker navigates to the audit log configuration settings within the Bitbucket administration panel.
4. The attacker modifies the audit log settings, such as disabling logging for specific event categories or reducing the log retention period.
5. The Bitbucket server processes the configuration change request.
6. Audit events related to the configuration change are logged (if auditing is still enabled for such events).
7. The attacker performs malicious activities, such as creating unauthorized repositories or exfiltrating source code, with reduced risk of detection.

## Impact

Successful modification of the Bitbucket audit log configuration allows attackers to operate with significantly reduced visibility. This can lead to delayed detection of breaches, prolonged dwell time, and increased data exfiltration. Without proper audit logging, organizations will struggle to identify the scope and impact of a compromise.

## Recommendation

*   Deploy the "Bitbucket Audit Log Configuration Updated" Sigma rule to your SIEM to detect changes to audit log configurations (logsource: bitbucket, service: audit).
*   Ensure Bitbucket audit logging is enabled at the "Basic" level or higher, as lower levels may not capture configuration changes (logsource: bitbucket, service: audit).
*   Investigate any detected instances of audit log configuration changes to determine if they are authorized (Sigma rule: "Bitbucket Audit Log Configuration Updated").
