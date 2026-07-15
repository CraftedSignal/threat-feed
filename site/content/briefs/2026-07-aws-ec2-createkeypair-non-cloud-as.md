---
title: Suspicious AWS EC2 Key Pair Creation from Non-Cloud Autonomous System
slug: 2026-07-aws-ec2-createkeypair-non-cloud-as
description: An Elastic detection rule identifies when a previously unseen AWS IAM principal successfully creates an EC2 key pair from an Autonomous System (AS) organization not associated with common cloud or hyperscaler providers, indicating potential attacker persistence or preparation for unauthorized instance access via SSH.
date: "2026-07-15T14:23:33Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - persistence
  - identity
vendors:
  - Amazon Web Services
products:
  - Amazon EC2
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Adversaries may call CreateKeyPair to stage SSH access material before launching or accessing instances.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: CreateKeyPair creates an Amazon EC2 SSH key pair in the account; the private key material is returned to the caller once. This is useful for persistence or preparation for instance access.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: CreateKeyPair creates an Amazon EC2 SSH key pair... This is useful for persistence or preparation for instance access. Hunt for RunInstances, ImportKeyPair, or Instance Connect activity involving the same key name or actor.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateKeyPair.html
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/persistence_new_terms_ec2_create_keypair_unusual_source_as.toml
rules:
  - title: AWS EC2 CreateKeyPair from Non-Cloud AS Organization
    description: Detects suspicious AWS EC2 CreateKeyPair API calls initiated by any IAM principal from an Autonomous System (AS) organization not associated with common cloud or hyperscaler providers. This behavior can indicate an adversary establishing persistence or preparing for instance access.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - lateral_movement
      - persistence
    techniques:
      - T1021
      - T1021.004
      - T1098
      - T1552
      - T1552.004
    data_sources:
      - cloud
      - aws.cloudtrail
rules_count: 1
---

Adversaries targeting AWS environments may attempt to establish persistence or prepare for unauthorized access to EC2 instances by creating new SSH key pairs. This brief details an Elastic detection rule designed to identify such suspicious activity. The rule triggers when an AWS IAM principal successfully executes the `CreateKeyPair` API call from a network whose Autonomous System (AS) organization is not a recognized cloud provider (such as Amazon, Google, or Microsoft). This detection is particularly sensitive as it focuses on the *first* time a given principal performs this action from an unusual source AS, which can be an early indicator of a compromised account being used to stage access materials. Defenders should investigate these alerts to determine if the activity aligns with legitimate operational changes or represents an attacker's attempt to gain a foothold.

## Attack Chain

1. **Initial Access:** An adversary gains unauthorized access to an AWS environment, often by compromising an IAM user or role via phishing, exposed credentials, or exploiting a vulnerable application.
2. **Credential Compromise:** The attacker acquires credentials for an existing IAM principal (user or role) within the target AWS account.
3. **Persistence Staging:** Using the compromised credentials, the attacker calls the `CreateKeyPair` API from an unusual network location (i.e., an AS organization not belonging to a major cloud provider). This action generates a new SSH key pair.
4. **Key Material Exfiltration:** The `CreateKeyPair` API returns the private key material to the caller. The attacker immediately downloads and stores this private key.
5. **SSH Access Preparation:** The newly created public key is associated with the AWS account, allowing it to be injected into new or existing EC2 instances.
6. **Lateral Movement/Persistence:** The attacker uses the exfiltrated private key to establish SSH connections to EC2 instances launched with, or updated to use, this key pair, thereby achieving persistence and enabling further malicious activities.
7. **Impact:** Once SSH access is established, the attacker can perform actions such as data exfiltration, deployment of malicious software, or further enumeration of the environment.

## Impact

If adversaries successfully create and leverage new EC2 key pairs from unusual network locations, it directly leads to unauthorized persistence and potential remote access to critical cloud infrastructure. This can enable a range of damaging activities, including data theft from EC2 instances or S3 buckets, resource hijacking for cryptocurrency mining, further privilege escalation within the AWS environment, or disruption of services. Such breaches can result in significant financial losses due to compromised data, operational downtime, and regulatory fines, alongside severe reputational damage. The ability to maintain access via SSH keys makes detection and remediation challenging, allowing attackers extended dwell time.

## Recommendation

* Deploy the Sigma rule `AWS_EC2_CreateKeyPair_New_Principal_Non_Cloud_AS` to your SIEM to detect suspicious `CreateKeyPair` activity.
* Ensure AWS CloudTrail logging is enabled and configured to capture `event.dataset: "aws.cloudtrail"` data, including `event.provider: "ec2.amazonaws.com"` and `event.action: "CreateKeyPair"`.
* Investigate all alerts generated by the `AWS_EC2_CreateKeyPair_New_Principal_Non_Cloud_AS` rule, examining `aws.cloudtrail.request_parameters`, `response_elements` for `keyName`, and correlating `source.ip`, `source.geo`, and `user_agent.original` with the principal’s normal administrative paths.
* If unauthorized activity is confirmed, delete the suspicious key pair using `DeleteKeyPair`, review IAM policies for `ec2:CreateKeyPair` permissions, and rotate any credentials used by the compromised IAM principal.
