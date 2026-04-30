---
title: AWS SecurityHub Findings Evasion via API Calls
slug: 2024-01-aws-securityhub-evasion
description: Attackers can impair defenses by modifying or deleting findings and insights within AWS SecurityHub using API calls such as BatchUpdateFindings, DeleteInsight, UpdateFindings, and UpdateInsight.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - cloud
  - securityhub
  - defense-evasion
vendors:
  - Amazon
products:
  - AWS Security Hub
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.003
    technique_name: 'Impair Defenses: Modify Cloud Firewall'
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.aws.amazon.com/cli/latest/reference/securityhub/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_securityhub_finding_evasion.yml
rules:
  - title: AWS SecurityHub BatchUpdateFindings API Call
    description: Detects calls to BatchUpdateFindings, which can be used to suppress or modify security findings.
    platform: sigma
    severity: high
    tactics:
      - defense_impairment
    techniques:
      - T1562.003
    data_sources:
      - aws
      - cloudtrail
  - title: AWS SecurityHub Insight Deletion
    description: Detects deletion of SecurityHub insights, potentially used to remove evidence of attacker activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_impairment
    techniques:
      - T1562
    data_sources:
      - aws
      - cloudtrail
  - title: AWS SecurityHub Findings Update
    description: Detects calls to UpdateFindings, which can be used to suppress or modify security findings.
    platform: sigma
    severity: high
    tactics:
      - defense_impairment
    techniques:
      - T1562.003
    data_sources:
      - aws
      - cloudtrail
rules_count: 3
---

Attackers with sufficient AWS privileges can manipulate SecurityHub findings to evade detection and maintain persistence within a compromised environment. This involves using SecurityHub's API to either modify existing findings, delete insights altogether, or update insights to mask malicious activity. This activity is conducted via API calls to `securityhub.amazonaws.com`, specifically targeting the `BatchUpdateFindings`, `DeleteInsight`, `UpdateFindings`, and `UpdateInsight` actions. Successful evasion allows malicious actors to operate without triggering alarms or attracting attention from security personnel, leading to prolonged compromise and potentially greater damage. This is especially critical in production environments where SecurityHub findings are actively monitored.

## Attack Chain

1.  The attacker gains initial access to an AWS account, potentially through compromised credentials or exploiting a misconfigured IAM role (T1078).
2.  The attacker enumerates existing SecurityHub findings and insights to identify potential targets for modification or deletion.
3.  The attacker calls the `BatchUpdateFindings` API to modify the severity, confidence, or resolution status of specific findings, effectively silencing alerts (T1562.003).
4.  Alternatively, the attacker calls the `UpdateFindings` API to modify individual findings.
5.  The attacker calls the `DeleteInsight` API to remove custom insights that could reveal their activities (T1562).
6.  As another option, the attacker calls the `UpdateInsight` API to modify the criteria of existing insights, causing them to miss malicious activities.
7.  The attacker validates the changes by querying SecurityHub to confirm that the targeted findings and insights have been successfully altered or removed.
8.  The attacker continues malicious activities, such as data exfiltration or lateral movement, with a reduced risk of detection due to the modified SecurityHub state (TA0005).

## Impact

Successful evasion of SecurityHub findings can lead to delayed incident response, prolonged attacker presence within the AWS environment, and increased data exfiltration or system compromise. The impact is particularly severe in production environments where SecurityHub is relied upon for real-time threat detection and alerting. By modifying or deleting findings, attackers can effectively blind security teams, enabling them to operate undetected for extended periods. The number of potential victims is directly proportional to the scale of AWS deployments relying on SecurityHub.

## Recommendation

*   Deploy the Sigma rule "AWS SecurityHub Findings Evasion" to your SIEM and tune for your environment to detect suspicious API calls related to findings manipulation (logsource: aws, service: cloudtrail).
*   Review and harden IAM policies to restrict access to SecurityHub API actions such as `BatchUpdateFindings`, `DeleteInsight`, `UpdateFindings`, and `UpdateInsight` to only authorized users and roles.
*   Implement multi-factor authentication (MFA) for all AWS accounts and roles, especially those with permissions to modify SecurityHub configurations.
*   Regularly audit CloudTrail logs for suspicious activity related to SecurityHub configuration changes.
