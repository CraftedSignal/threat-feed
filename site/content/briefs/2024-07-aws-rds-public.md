---
title: AWS RDS DB Instance Made Public
slug: 2024-07-aws-rds-public
description: An attacker with compromised AWS credentials may modify an Amazon RDS DB instance or cluster to be publicly accessible for persistence, data exfiltration, or to bypass network restrictions.
date: "2024-07-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - rds
  - persistence
  - defense_evasion
vendors:
  - AWS
products:
  - AWS RDS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1133
    technique_name: External Remote Services
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1556
    technique_name: Modify Authentication Process
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1133
    technique_name: External Remote Services
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/persistence_rds_instance_made_public.toml
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBInstance.html
  - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.DBInstance.Modifying.html
  - https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-persistence/aws-rds-persistence#make-instance-publicly-accessible-rds-modifydbinstance
  - https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-rds-privesc#rds-createdbinstance
  - https://github.com/aws-samples/aws-incident-response-playbooks/blob/c151b0dc091755fffd4d662a8f29e2f6794da52c/playbooks/
  - https://github.com/aws-samples/aws-customer-playbook-framework/tree/a8c7b313636b406a375952ac00b2d68e89a991f2/docs
  - https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/
rules:
  - title: AWS RDS Instance Publicly Accessible via ModifyDBInstance
    description: Detects when an Amazon RDS DB instance is modified to be publicly accessible.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1133
      - T1556
      - T1556.009
    data_sources:
      - cloudtrail
      - aws
  - title: AWS RDS Instance Created as Publicly Accessible
    description: Detects when an Amazon RDS DB instance or cluster is created with public accessibility enabled.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1133
      - T1556
      - T1556.009
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies the creation or modification of an Amazon RDS DB instance or cluster with the `publiclyAccessible` attribute set to `true`. While legitimate use cases exist, unexpected public exposure of a database to the internet introduces significant security risks. An adversary with access to AWS credentials might modify a DB instance's public accessibility to exfiltrate data, establish persistence, or bypass internal network restrictions. The rule focuses on `ModifyDBInstance`, `CreateDBInstance`, and `CreateDBCluster` events within AWS CloudTrail logs. Defenders should investigate any unexpected changes to RDS instance accessibility. This activity can indicate compromised credentials or insider threats, and might be correlated with other IAM and network configuration changes to assess the overall impact.

## Attack Chain

1. An attacker gains unauthorized access to AWS credentials (e.g., via phishing or credential stuffing).
2. The attacker uses the compromised credentials to authenticate to the AWS Management Console or via the AWS CLI/API.
3. The attacker identifies a target RDS DB instance or cluster.
4. The attacker executes a `ModifyDBInstance` API call, setting the `PubliclyAccessible` parameter to `true` in the `request_parameters`.
5. Alternatively, the attacker executes a `CreateDBInstance` or `CreateDBCluster` API call with the `PubliclyAccessible` parameter set to `true`.
6. The attacker modifies associated security groups using `AuthorizeSecurityGroupIngress` to allow inbound traffic from `0.0.0.0/0` or other broad IP ranges.
7. The now publicly accessible RDS instance is used to exfiltrate data or as a pivot point to attack other internal resources.
8. The attacker leverages the publicly exposed database for persistent access and further reconnaissance.

## Impact

If an attacker successfully makes an RDS DB instance publicly accessible, they can potentially exfiltrate sensitive data, pivot to other internal resources, or establish persistent access to the environment. The number of affected instances depends on the scope of the credential compromise. Sectors that heavily rely on cloud infrastructure, such as finance, healthcare, and technology, are at higher risk. The impact can range from data breaches and compliance violations to significant financial losses and reputational damage.

## Recommendation

*   Deploy the Sigma rule "AWS RDS DB Instance Made Public" to your SIEM using `filebeat-*` and `logs-aws.cloudtrail-*` indices to detect modifications to RDS instance accessibility.
*   Review `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.type` in the SIEM to identify the IAM principal that made the change and validate its legitimacy.
*   Monitor for `AuthorizeSecurityGroupIngress` events in CloudTrail logs that allow inbound traffic from `0.0.0.0/0` to associated security groups of RDS instances.
*   Implement AWS Config rules (e.g., `rds-instance-public-access-check`) to automatically detect and remediate publicly accessible RDS instances.
*   Enforce Service Control Policies (SCPs) to prevent the creation of publicly accessible RDS instances.
*   Refer to the provided AWS IR Playbooks and AWS Customer Playbook Framework documentation for incident response guidance.
