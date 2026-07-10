---
title: AWS IAM Default Policy Version Modification
slug: 2024-01-aws-iam-policy-version
description: An adversary modifies the default version of an AWS IAM policy, potentially downgrading security or disrupting access control.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - iam
  - policy
vendors:
  - Amazon Web Services
products:
  - AWS Identity and Access Management
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/aws_setdefaultpolicyversion.yml
rules:
  - title: Detect AWS IAM Set Default Policy Version
    description: Detects the use of the 'SetDefaultPolicyVersion' API call which modifies the default IAM policy version.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS IAM Policy Version Creation Followed by Set Default
    description: Detects if a new IAM policy version is created and then immediately set as the default version, which can indicate malicious policy manipulation.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

The modification of the default AWS IAM policy version can be an indicator of malicious activity, potentially performed by an insider threat or an attacker who has gained unauthorized access to an AWS account. While the provided source material lacks specific details on observed campaigns, the ability to modify the default policy version allows for subtle changes to permissions that may go unnoticed. An attacker could revert to a less restrictive version of a policy or introduce a new, permissive version as the default, thereby weakening the security posture of the AWS environment. This can facilitate privilege escalation, data exfiltration, or other malicious activities. Detecting such modifications is crucial for maintaining the integrity and security of AWS environments.

## Attack Chain

1.  Attacker gains access to AWS Management Console or uses compromised AWS CLI credentials.
2.  Attacker identifies a target IAM policy to modify, querying IAM policies to find a suitable target.
3.  Attacker retrieves the current default policy version ARN using AWS API calls.
4.  Attacker crafts a modified IAM policy version with reduced permissions or unintended access.
5.  Attacker creates a new IAM policy version using the AWS API, while keeping the original intact.
6.  Attacker uses the `aws iam set-default-policy-version` command to set the newly crafted policy version as the default.
7.  Legitimate users or services relying on the IAM policy now operate under the modified (potentially weakened) permissions.
8.  Attacker leverages the broadened permissions for lateral movement, data access, or other malicious objectives.

## Impact

Successful modification of the default IAM policy version can lead to privilege escalation, unauthorized access to sensitive data, and potential disruption of services relying on the affected policy. The impact depends on the scope of the policy and the permissions altered. A successful attack can affect multiple AWS services and resources governed by the modified policy. The change can be subtle and persist for a long time if not detected, leading to significant data breaches or service outages.
