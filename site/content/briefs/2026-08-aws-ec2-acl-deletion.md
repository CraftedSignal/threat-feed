---
title: AWS EC2 Network ACL Deletion Defense Evasion
slug: 2026-08-aws-ec2-acl-deletion
description: Adversaries may delete AWS EC2 Network Access Control Lists (ACLs) or their ingress/egress entries to disable network-level security controls and facilitate unauthorized access or data exfiltration.
date: "2026-08-24T09:46:04Z"
lastmod: "2026-08-24T09:51:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - defense-evasion
  - aws
  - discovery
  - credential-access
  - ebs
  - encryption
  - impact
  - persistence
vendors:
  - Amazon
products:
  - AWS EC2
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Adversaries may delete these ACLs to disable security controls, facilitating unauthorized access or data exfiltration.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
    evidence: Adversaries may use this information to gather sensitive data from the instance such as hardcoded credentials or to identify potential vulnerabilities.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The userData field can contain sensitive information, such as hardcoded credentials or configuration scripts, that adversaries may exploit for further attacks.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: Adversaries may disable encryption to weaken data protection before exfiltrating or tampering with EBS volumes or snapshots.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
    evidence: Disabling this setting introduces significant risk as all future volumes created in that region will be unencrypted by default, potentially exposing sensitive data at rest.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1133
    technique_name: External Remote Services
    evidence: Threat actors may abuse this to establish persistence, exfiltrate data, or pivot in an AWS environment.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.007
    technique_name: Disable or Modify Cloud Firewall
    evidence: Modifications to a security group configuration could expose critical assets to unauthorized access.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578.005
    technique_name: Modify Cloud Compute Configurations
    evidence: Modifying configurations may allow unauthorized access.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
    evidence: Adversaries may exploit route tables to reroute traffic for data exfiltration or to establish persistence by creating unauthorized routes.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstanceAttribute.html
  - https://hackingthe.cloud/aws/exploitation/local_ec2_priv_esc_through_user_data
  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html
  - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/disable-ebs-encryption-by-default.html
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DisableEbsEncryptionByDefault.html
  - https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/ec2-security-groups.html
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/persistence_route_table_created.toml
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateRoute.html
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateRouteTable
rules:
  - title: Detect AWS EC2 Network ACL Deletion
    description: Detects successful deletion of an EC2 Network ACL or ACL entry, excluding activity from known infrastructure-as-code tools.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.007
    data_sources:
      - cloud
      - aws
  - title: Detect Unauthorized AWS EC2 User Data Retrieval
    description: Detects the first time an IAM user or role requests the userData attribute for an EC2 instance in AWS CloudTrail, excluding known automation tools.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1552.005
      - T1580
    data_sources:
      - cloud
      - aws
  - title: Detect AWS EBS Encryption Disabled
    description: Detects when the Amazon EBS encryption by default setting is disabled in an AWS region via CloudTrail.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
      - impact
    techniques:
      - T1565.001
      - T1578.005
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Unauthorized AWS EC2 Security Group Changes
    description: Detects unauthorized modifications to AWS EC2 security groups using CloudTrail logs, excluding known automated configuration management tools.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1562.007
    data_sources:
      - cloud
  - title: AWS EC2 Route Table Creation
    description: Detects the creation of EC2 route tables or routes, which may indicate malicious persistence or traffic interception.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1578.005
    data_sources:
      - cloud
      - aws
rules_count: 5
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review CloudTrail for historical ACL deletions
      owner: SOC
      due: 48h
      evidence: General threat intelligence on cloud defense evasion
  hunt_leads:
    - lead: Identify accounts performing high volumes of network modifications
      technique_id: T1562.007
      data_needed:
        - CloudTrail Management Events
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Analysis of cloud environment logs for unauthorized firewall changes
updates:
  - at: "2026-08-24T09:46:59Z"
    level: L1
    summary: 'added detection rule: Detect Unauthorized AWS EC2 User Data Retrieval'
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/discovery_ec2_userdata_request_for_ec2_instance.toml
  - at: "2026-08-24T09:49:27Z"
    level: L1
    summary: 'added detection rule: Detect AWS EBS Encryption Disabled'
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/impact_ec2_disable_ebs_encryption.toml
  - at: "2026-08-24T09:50:43Z"
    level: L1
    summary: 'added detection rule: Detect Unauthorized AWS EC2 Security Group Changes'
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/persistence_ec2_security_group_configuration_change_detection.toml
  - at: "2026-08-24T09:51:20Z"
    level: L1
    summary: 'added detection rule: AWS EC2 Route Table Creation'
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/persistence_route_table_created.toml
---

Adversaries targeting AWS environments may attempt to impair security defenses by modifying or deleting Network Access Control Lists (ACLs) within a Virtual Private Cloud (VPC). By removing these firewall layers, attackers can bypass traffic filtering, enable lateral movement, or facilitate the exfiltration of sensitive data. This activity typically manifests as API calls within AWS CloudTrail, specifically targeting the `DeleteNetworkAcl` or `DeleteNetworkAclEntry` actions. Because Network ACLs are critical for subnet security, unauthorized deletions are significant indicators of potential defense evasion. Organizations must distinguish these malicious modifications from legitimate infrastructure-as-code (IaC) updates, such as those performed by Terraform, Pulumi, or Ansible, which may legitimately manage network configurations in automated environments.

## Impact

Successful deletion of Network ACLs exposes subnets to unauthorized inbound and outbound traffic, effectively nullifying intended network security perimeters. This can result in unauthorized access to sensitive internal resources, facilitate command-and-control communication, or enable the unauthorized exfiltration of data from the affected VPC subnets.

## Recommendation

- Deploy the Sigma-compatible rule below to monitor for unauthorized Network ACL deletions in AWS CloudTrail logs.
- Establish a baseline of authorized administrative and IaC service accounts to tune out legitimate network configuration changes.
- Implement AWS CloudTrail alerts for `DeleteNetworkAcl` and `DeleteNetworkAclEntry` events, prioritizing alerts that lack association with recognized automated deployment roles.
- Review IAM policies to ensure that only essential roles possess permissions for `ec2:DeleteNetworkAcl` and `ec2:DeleteNetworkAclEntry` actions.
- Enable VPC Flow Logs to monitor traffic patterns following any detected modifications to network security configurations.
