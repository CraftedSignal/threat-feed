---
title: Defense Evasion via Disabling AWS Security Hub
slug: 2026-09-aws-security-hub-disabled
description: Threat actors disable AWS Security Hub to suppress centralized security findings and compliance monitoring, facilitating stealthy data exfiltration or ransomware deployment.
date: "2026-09-08T07:31:45Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud-security
  - defense-evasion
  - aws
vendors:
  - Amazon
products:
  - AWS Security Hub
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Disabling it suppresses centralized finding aggregation and compliance checks, removing visibility into threats across the account.
    confidence_band: high
rules:
  - title: Detect AWS Security Hub Disablement
    description: Detects the successful execution of the DisableSecurityHub API call, which stops security finding aggregation and compliance monitoring.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - cloud
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection rule to monitor for DisableSecurityHub API activity.
      owner: Detection Engineering
      due: 24h
      evidence: Source provides KQL query for detection.
  hunt_leads:
    - lead: Unauthorized DisableSecurityHub calls followed by other security service teardown API actions.
      technique_id: T1562.001
      data_needed:
        - CloudTrail Management Events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Multi-service security teardown is high confidence ransomware/wiperware preparation.
---

Attackers target AWS Security Hub to blind security operations teams by breaking the centralized aggregation of findings from services such as Amazon GuardDuty, Amazon Inspector, AWS IAM Access Analyzer, and Amazon Macie. Disabling Security Hub via the 'DisableSecurityHub' API call is a highly effective defense evasion technique that immediately stops the generation of new findings and halts continuous compliance checks. This activity is frequently observed as a precursor to high-impact malicious operations, including ransomware deployment and large-scale data exfiltration, where the attacker seeks to minimize the likelihood of detection by security platforms. Security teams should monitor for this activity within CloudTrail logs to identify potential credential misuse or unauthorized administrative changes.

## Attack Chain

1. Attacker gains initial access to an AWS environment, typically through compromised IAM access keys or over-privileged identity roles.
2. Attacker performs reconnaissance to identify enabled security services and monitoring capabilities.
3. Attacker targets centralized logging and monitoring services to reduce noise and prevent automated alerting.
4. Attacker executes the 'DisableSecurityHub' API call to cease security findings aggregation.
5. Attacker proceeds to disable additional services such as GuardDuty or Macie, or modifies Event Selectors to further minimize activity logging.
6. Attacker initiates the primary objective, such as deploying ransomware, exfiltrating data, or creating backdoors for persistence.

## Impact

Successful exploitation results in total loss of visibility into automated security findings and compliance posture for the targeted AWS account. This blind spot allows attackers to move laterally, exfiltrate data, or deploy malicious infrastructure without triggering existing automated response or alerting workflows that rely on Security Hub integration.

## Recommendation

Prioritized actions for detection engineering and security operations teams:
- Deploy the provided Sigma rule to monitor for 'DisableSecurityHub' events in CloudTrail logs.
- Establish alerting for high-risk API calls such as 'DeleteDetector' (GuardDuty), 'DisableMacie', or 'DeleteTrail'.
- Verify existing AWS Config rules are enabled to trigger alerts on security service configuration changes.
- Audit IAM identities with 'securityhub:DisableSecurityHub' permissions and restrict access to the minimum required for legitimate operations.
- Investigate any 'DisableSecurityHub' event that does not correlate with a known change management ticket or authorized operational window.
