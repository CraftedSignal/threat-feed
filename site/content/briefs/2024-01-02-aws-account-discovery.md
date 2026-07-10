---
title: AWS Account Discovery By Rare User
slug: 2024-01-02-aws-account-discovery
description: Detects the first-time enumeration of AWS Organizations or IAM accounts by a user, potentially indicating reconnaissance by compromised credentials.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - aws
  - discovery
  - account-enumeration
vendors:
  - AWS
products:
  - AWS
  - AWS Organizations
  - AWS IAM
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
references:
  - https://kudelskisecurity.com/research/investigating-two-variants-of-the-trivy-supply-chain-compromise
  - https://github.com/RhinoSecurityLabs/pacu/blob/master/pacu/modules/organizations__enum/main.py
  - https://attack.mitre.org/techniques/T1087/
  - https://attack.mitre.org/techniques/T1087/004/
  - https://attack.mitre.org/techniques/T1580/
  - https://github.com/aws-samples/aws-incident-response-playbooks
rules:
  - title: AWS Account Discovery By Rare User
    description: Detects AWS Organization and IAM account enumeration API calls from a rare user.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1087.004
      - T1580
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Account Discovery via IAM and Organizations - Filtered
    description: Detects AWS account enumeration via IAM or Organizations, excluding AWSService and console access.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1087.004
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies when a user performs AWS Organizations or IAM account enumeration API calls for the first time within a defined lookback window. Attackers who have compromised credentials often map out an organization's structure, including accounts, organizational units (OUs), roots, and delegated administrators, as well as account-level metadata like aliases, using the AWS CLI or SDKs. This activity is detected via a New Terms rule, focusing on rare occurrences of a `cloud.account.id` and `user.name` pair associated with these enumeration actions. The rule aims to highlight potentially malicious reconnaissance activities within an AWS environment by identifying unusual account discovery patterns. This detection is relevant for AWS environments and relies on CloudTrail logs.

## Attack Chain

1.  An attacker gains unauthorized access to AWS credentials through methods such as phishing or credential stuffing.
2.  The attacker uses the compromised credentials to authenticate to the AWS environment, likely through the AWS CLI or SDK.
3.  The attacker executes AWS CLI commands or SDK calls to enumerate the organization structure, starting with `DescribeOrganization` or `ListAccounts`.
4.  The attacker may then proceed to enumerate Organizational Units using `ListOrganizationalUnitsForParent`.
5.  The attacker gathers account-level information, such as aliases, using `ListAccountAliases` or `GetAccountSummary`.
6.  The attacker reviews IAM policies and roles using actions such as `ListPolicies`.
7.  The attacker analyzes the gathered information to identify potential targets or weaknesses within the AWS environment.

## Impact

A successful AWS account discovery can lead to significant breaches. Attackers can identify critical assets, privilege escalation paths, and potential vulnerabilities within the AWS environment. This information can be used to move laterally, exfiltrate sensitive data, or deploy malicious infrastructure. The impact is amplified in multi-account environments, where attackers can map out the entire organization structure.

## Recommendation

*   Deploy the Sigma rule `AWS Account Discovery By Rare User` to your SIEM and tune the threshold and lookback window for your environment.
*   Review the investigation guide linked in the rule's note section, especially the "Possible investigation steps" which details important fields to investigate.
*   Filter out known good `user.name` and `cloud.account.id` pairs by adding exceptions to the Sigma rule.
*   Monitor CloudTrail logs for unusual API calls related to account enumeration, focusing on the actions listed in the rule query.
*   Enforce the principle of least privilege for IAM roles and policies to limit the scope of potential damage from compromised credentials.
