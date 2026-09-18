---
title: Detection of Unauthorized Public Exposure of AWS RDS Instances
slug: 2026-09-aws-rds-public-access
description: Adversaries with compromised AWS credentials may set the publiclyAccessible attribute to true during RDS instance creation or modification to facilitate data exfiltration, establish persistence, or bypass internal network boundaries.
date: "2026-09-18T19:40:53Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - cloud
  - persistence
  - defense-evasion
vendors:
  - Amazon
products:
  - RDS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1133
    technique_name: External Remote Services
    evidence: Adversaries may enable public access on an existing instance... to establish persistence.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1556
    technique_name: Modify Authentication Process
    evidence: Adversaries may enable public access... to bypass internal access controls.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/persistence_rds_instance_made_public.toml
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBInstance.html
  - https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-persistence/aws-rds-persistence#make-instance-publicly-accessible-rds-modifydbinstance
rules:
  - title: Detect AWS RDS Instance Set to Publicly Accessible
    description: Detects the creation or modification of an AWS RDS instance or cluster with publiclyAccessible set to true, excluding activity originating from known IaC tools.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1133
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable the provided detection rule in SIEM.
      owner: Detection Engineering
      due: 24h
      evidence: Rule ID 9efb3f79-b77b-466a-9fa0-3645d22d1e7f
  mitigation_plan:
    - priority: immediate
      action: Implement SCPs to deny public RDS accessibility.
      owner: Cloud Security
      addresses: Prevention of unauthorized RDS public exposure
      evidence: AWS best practices for RDS security
---

Adversaries who obtain unauthorized access to AWS credentials may leverage Amazon RDS configuration changes to compromise cloud environments. By enabling the publiclyAccessible attribute on a new or existing database instance, an attacker exposes the database endpoint directly to the public internet. This misconfiguration bypasses private VPC network controls, potentially allowing an attacker to exfiltrate database contents or use the instance as a bridge for further network lateral movement. This threat is particularly relevant in environments where database security relies on network isolation rather than robust, independent authentication and encryption controls. Defenders should focus on identifying modifications performed by unexpected IAM principals or those originating from suspicious source IP addresses and user agents that bypass standard infrastructure-as-code deployment pipelines.

## Attack Chain

1. Attacker gains initial access to AWS environment via stolen IAM access keys or session tokens.
2. Attacker enumerates existing RDS instances using API calls like DescribeDBInstances.
3. Attacker identifies a target database instance containing sensitive information.
4. Attacker invokes the ModifyDBInstance API to set the publiclyAccessible attribute to true.
5. Attacker simultaneously modifies security group ingress rules via AuthorizeSecurityGroupIngress to allow external connections.
6. Attacker connects to the exposed database endpoint over the public internet to dump data or deploy malicious stored procedures.
7. Attacker maintains long-term persistence by utilizing the public database endpoint as a staging or exfiltration point.

## Impact

Successful exploitation leads to unauthorized data exfiltration, the loss of confidentiality for sensitive database content, and the potential compromise of internal network security postures. Victims include any organization utilizing AWS RDS without strict Service Control Policies (SCPs) preventing public accessibility.

## Recommendation

- Implement AWS SCPs to explicitly deny the ability for any principal to modify the publiclyAccessible attribute to true for RDS instances.
- Deploy the provided detection logic to AWS CloudTrail logs to alert on unauthorized configuration changes in real-time.
- Utilize AWS Config rules (rds-instance-public-access-check) to automatically remediate or flag publicly accessible instances.
- Review all CloudTrail activity associated with IAM principals that perform modification actions on RDS infrastructure to identify anomalous behavior patterns.
