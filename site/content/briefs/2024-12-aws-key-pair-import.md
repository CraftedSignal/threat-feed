---
title: Suspicious AWS EC2 Key Pair Import Activity
slug: 2024-12-aws-key-pair-import
description: The import of SSH key pairs into AWS EC2, as detected by CloudTrail logs, may indicate unauthorized access attempts, persistence establishment, or privilege escalation by an attacker.
date: "2024-12-19T00:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - aws
  - cloudtrail
  - ec2
  - keypair
  - initial-access
  - persistence
  - privilege-escalation
vendors:
  - Amazon
products:
  - Elastic Compute Cloud (EC2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ImportKeyPair.html
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_ec2_import_key_pair_activity.yml
rules:
  - title: AWS EC2 Key Pair Import Activity
    description: Detects the import of SSH key pairs into AWS EC2, potentially indicating unauthorized access attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
    techniques:
      - T1078
    data_sources:
      - aws
      - cloudtrail
  - title: AWS EC2 Key Pair Creation Followed by Import
    description: Detects a pattern where a key pair is first created and then immediately imported, which could indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
    techniques:
      - T1078
    data_sources:
      - aws
      - cloudtrail
rules_count: 2
---

The unauthorized import of SSH key pairs into Amazon Elastic Compute Cloud (EC2) is a technique that malicious actors can leverage to gain unauthorized access to EC2 instances. By importing their own key pairs, attackers can bypass existing security measures and gain persistent access to compromised systems. This activity is often part of a broader attack campaign aimed at compromising sensitive data, disrupting services, or establishing a foothold within an organization's cloud infrastructure. The initial publication of the detection rule was in December 2024, highlighting the ongoing relevance of this technique in cloud security. Monitoring for this activity can help defenders identify and respond to potential security breaches in a timely manner.

## Attack Chain

1. An attacker gains initial access to an AWS account, potentially through compromised credentials or exploiting a misconfigured IAM role.
2. The attacker attempts to enumerate existing EC2 instances to identify potential targets.
3. The attacker generates or obtains an SSH key pair, which they intend to use for unauthorized access.
4. The attacker uses the `ImportKeyPair` API call within the EC2 service to import the generated or obtained SSH key pair.
5. The attacker modifies the EC2 instance's configuration to associate the newly imported key pair with the instance. This might involve stopping and restarting the instance.
6. The attacker uses the imported SSH key pair to gain SSH access to the EC2 instance.
7. Once inside the instance, the attacker attempts to escalate privileges and move laterally within the AWS environment.
8. The attacker exfiltrates sensitive data, deploys malware, or disrupts critical services.

## Impact

A successful key pair import can lead to complete compromise of the affected EC2 instances, potentially impacting dozens of servers depending on the environment. Sensitive data stored on or accessible from these instances could be exfiltrated, leading to financial loss, reputational damage, and regulatory fines. Furthermore, compromised instances can be used as a launchpad for further attacks within the AWS environment, leading to a wider breach. The financial impact can range from tens of thousands to millions of dollars, depending on the scale of the breach and the sensitivity of the data compromised.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect `ImportKeyPair` events in CloudTrail logs (logsource: aws, service: cloudtrail).
*   Review IAM policies to ensure that only authorized users and roles have the necessary permissions to import key pairs (eventSource: 'ec2.amazonaws.com', eventName: 'ImportKeyPair').
*   Investigate any detected `ImportKeyPair` events, validating the user identity, user agent, and source IP address to ensure they are expected (detection block).
*   Implement multi-factor authentication (MFA) for all AWS accounts to reduce the risk of credential compromise.
