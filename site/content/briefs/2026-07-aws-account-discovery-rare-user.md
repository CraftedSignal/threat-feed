---
title: AWS Account Discovery By Rare User
slug: 2026-07-aws-account-discovery-rare-user
description: A new detection rule identifies rare instances where an identity performs AWS Organizations or IAM account enumeration APIs for the first time within a specified lookback window, indicative of an attacker attempting to map the AWS environment after compromising credentials.
date: "2026-07-20T13:08:54Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - aws
  - discovery
  - identity
  - reconnaissance
vendors:
  - Amazon
products:
  - AWS Organizations
  - AWS IAM
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: Identifies the first time, within a lookback window, an identity performs AWS Organizations or IAM account enumeration APIs.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
    evidence: Attackers with compromised credentials often map the organization (accounts, OUs, roots, delegated admins) and account-level metadata (aliases, summary) using the AWS CLI or SDKs.
    confidence_band: high
references:
  - https://kudelskisecurity.com/research/investigating-two-variants-of-the-trivy-supply-chain-compromise
  - https://github.com/RhinoSecurityLabs/pacu/blob/master/pacu/modules/organizations__enum/main.py
rules:
  - title: AWS Account Discovery By Rare User
    description: Detects the execution of AWS Organizations or IAM account enumeration APIs by a user identity, which is often an early stage of reconnaissance by attackers after credential compromise. This rule identifies such activities that are rare or unusual for a specific account and user.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1087
      - T1087.004
      - T1580
    data_sources:
      - cloud
      - aws
rules_count: 1
---

This detection brief highlights a new rule designed to identify unusual AWS account discovery activities by users or identities that have not previously performed such actions. Threat actors with compromised credentials commonly execute AWS Organizations and IAM account enumeration APIs to map the victim's cloud environment. This includes gathering information about accounts, organizational units, roots, delegated administrators, and account-level metadata such as aliases and summaries. The detection rule specifically targets the first occurrence of a unique `cloud.account.id` and `user.name` pair performing these sensitive discovery operations within a defined historical window. This type of reconnaissance is a critical step in an attacker's kill chain, enabling them to understand the environment for subsequent privilege escalation, lateral movement, or data exfiltration.

## Attack Chain

1. **Initial Access**: An attacker gains access to an AWS environment, typically through compromised user credentials (e.g., IAM user access keys, temporary session tokens) obtained via phishing, malware, or exploiting misconfigurations.
2. **Discovery (Reconnaissance)**: With compromised credentials, the attacker begins to enumerate the AWS environment to understand its structure and identify high-value targets or misconfigurations.
3. **AWS Organizations Enumeration**: The attacker executes API calls such as `DescribeOrganization`, `ListAccounts`, `ListRoots`, `ListOrganizationalUnitsForParent`, `ListAWSServiceAccessForOrganization`, `ListDelegatedAdministrators`, `ListDelegatedServicesForAccount`, and `DescribeResourcePolicy` to map the multi-account structure, organizational units, and policy relationships.
4. **AWS IAM Account Enumeration**: Concurrently or sequentially, the attacker performs API calls like `ListAccountAliases` and `GetAccountSummary` to gather details about the specific AWS account they have access to.
5. **Information Gathering**: The collected information provides a comprehensive understanding of the AWS topology, available resources, and potential pathways for privilege escalation or lateral movement.
6. **Follow-on Actions**: Based on the discovery, the attacker plans and executes further malicious activities, which could include privilege escalation, resource modification, data exfiltration, or deployment of additional malicious tools.

## Impact

Successful AWS account discovery provides attackers with a detailed blueprint of an organization's cloud infrastructure, enabling them to identify critical assets, misconfigurations, and potential avenues for further compromise. This reconnaissance phase directly facilitates more severe impacts such as unauthorized access to sensitive data, disruption of critical cloud services, resource exfiltration, or deployment of cryptocurrency miners. While discovery itself is not destructive, it is a crucial precursor that significantly increases the likelihood and severity of subsequent attacks, potentially leading to financial losses, reputational damage, and operational disruption.

## Recommendation

* Deploy the Sigma rule "AWS Account Discovery By Rare User" provided in this brief to your SIEM and tune for your environment.
* Ensure `logs-aws.cloudtrail-*` data is being ingested to activate the detection rule.
* Investigate alerts from the Sigma rule by confirming the `user.name` and `aws.cloudtrail.user_identity.arn` and their normal activity patterns.
* Review `source.ip` and `user_agent.original` for any unfamiliar tooling or locations associated with the detected activity.
* Correlate these discovery events with other activities such as STS (`GetCallerIdentity`, `AssumeRole`) calls or privilege changes within the same session.
* If the activity is unexpected, immediately rotate credentials for the implicated principal and review CloudTrail logs for any follow-on API activity.
* Tighten least privilege on Organizations and IAM read APIs where appropriate to limit the scope of such discovery actions.
