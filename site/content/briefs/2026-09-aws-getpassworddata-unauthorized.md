---
title: Detection of Unauthorized AWS EC2 GetPasswordData API Access
slug: 2026-09-aws-getpassworddata-unauthorized
description: Adversaries may attempt to retrieve EC2 administrator passwords via the GetPasswordData API to facilitate privilege escalation or lateral movement within AWS environments.
date: "2026-09-18T19:25:10Z"
lastmod: "2026-09-19T13:18:37Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - cloud
  - credential-access
  - identity-and-access-audit
  - incident-response
  - ransomware
  - persistence
  - defense-evasion
  - cloud-security
  - discovery
  - credential-validation
vendors:
  - Amazon
products:
  - AWS EC2
  - AWS STS
  - EC2
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Adversaries may use this API call to escalate privileges or move laterally within EC2 instances.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Adversaries may use this API call to escalate privileges or move laterally within EC2 instances.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: Adversaries may attempt to remove access to snapshots in order to prevent legitimate users or automated processes from accessing or restoring from snapshots.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Restricting snapshot access may help adversaries cover their tracks by making it harder for defenders to analyze or recover deleted or altered data.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578.005
    technique_name: Modify Cloud Compute Configurations
    evidence: This tactic can also be used to evade detection or maintain exclusive access to critical backups.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1133
    technique_name: External Remote Services
    evidence: Adversaries may exploit ACLs to establish persistence or exfiltrate data by creating permissive rules.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Adversaries may exploit ACLs to establish persistence or exfiltrate data by creating permissive rules.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
    evidence: Adversaries may exploit ACLs to establish persistence or exfiltrate data by creating permissive rules.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: Adversaries who steal instance role credentials often verify them with GetCallerIdentity from infrastructure outside your normal egress paths.
    confidence_band: high
references:
  - https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-ec2-privesc
  - https://attack.mitre.org/techniques/T1552/005/
  - https://docs.aws.amazon.com/ebs/latest/userguide/ebs-modifying-snapshot-permissions.html
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifySnapshotAttribute.html
  - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/create-network-acl.html
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateNetworkAcl.html
  - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/create-network-acl-entry.html
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateNetworkAclEntry.html
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/credential_access_aws_getpassword_for_ec2_instance.toml
rules:
  - title: AWS EC2 Unauthorized Admin Credential Fetch via Assumed Role
    description: Detects unauthorized attempts by an AWS role to use GetPasswordData to access the administrator password of an EC2 instance, indicated by an UnauthorizedOperation error.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - privilege_escalation
    techniques:
      - T1078.004
      - T1552.005
    data_sources:
      - cloudtrail
      - aws
  - title: AWS EC2 EBS Snapshot Access Removed
    description: Detects when access is removed for an AWS EC2 EBS snapshot, which may indicate an attempt to inhibit system recovery.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - webserver
  - title: Detect Unauthorized AWS Network ACL Creation
    description: Detects the creation of an AWS EC2 network access control list (ACL) or an entry in a network ACL by users not identified as known automation tools.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1562.007
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS EC2 Role GetCallerIdentity from New Source AS
    description: Detects the first time an EC2 instance role session calls AWS STS GetCallerIdentity from a source AS organization not seen in the previous 10 days, excluding standard Amazon and Google infrastructure.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1087.004
    data_sources:
      - webserver
rules_count: 4
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to monitor CloudTrail for UnauthorizedOperation errors on GetPasswordData.
      owner: Detection Engineering
      due: 48h
      evidence: Rule defined in brief
  hunt_leads:
    - lead: Search logs for any occurrence of GetPasswordData by non-standard or highly privileged user roles.
      technique_id: T1552.005
      data_needed:
        - AWS CloudTrail logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source description of potential privilege escalation
  mitigation_plan:
    - priority: immediate
      action: Audit and restrict IAM policies containing the ec2:GetPasswordData action.
      owner: IT Operations
      addresses: T1552.005
      evidence: Source guidance on Principle of Least Privilege
updates:
  - at: "2026-09-18T19:35:03Z"
    level: L1
    summary: 'added detection rule: AWS EC2 EBS Snapshot Access Removed'
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/impact_ec2_ebs_snapshot_access_removed.toml
  - at: "2026-09-18T19:38:21Z"
    level: L1
    summary: 'added detection rule: Detect Unauthorized AWS Network ACL Creation'
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/persistence_ec2_network_acl_creation.toml
  - at: "2026-09-19T01:06:23Z"
    level: L1
    summary: 'added detection rule: Detect AWS EC2 Role GetCallerIdentity from New Source AS'
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/discovery_new_terms_sts_getcalleridentity_ec2_role_new_source_as.toml
  - at: "2026-09-19T13:18:37Z"
    level: L1
    summary: new product
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/credential_access_aws_getpassword_for_ec2_instance.toml
---

This threat brief identifies the risk of unauthorized use of the `GetPasswordData` API call within AWS environments. Adversaries who have gained initial access to a cloud account through compromised or over-privileged credentials may attempt to leverage this API to obtain the initial administrator password for Windows-based EC2 instances. This technique is often used to facilitate privilege escalation or lateral movement across the target network. While the API is a legitimate feature for system administration, its use by unexpected or unauthorized IAM roles is a high-signal indicator of reconnaissance or exploitation. Organizations should monitor for `Client.UnauthorizedOperation` errors returned by CloudTrail for this specific API call to identify potential malicious intent by threat actors attempting to discover misconfigured or highly privileged instance credentials.

## Impact

Successful exploitation allows an adversary to obtain plaintext administrator credentials for EC2 instances, leading to full compromise of the affected compute resources. This can result in further data exfiltration, movement within the internal VPC, and persistence within the cloud environment. Organizations across all sectors utilizing AWS EC2 are potentially affected if IAM policies are overly permissive.

## Recommendation

Detection engineering teams should prioritize identifying anomalous API usage related to instance metadata and credential management.

- Deploy the provided detection logic to monitor AWS CloudTrail logs for unauthorized `GetPasswordData` events.
- Review IAM roles currently holding `ec2:GetPasswordData` permissions and enforce the principle of least privilege.
- Establish alerting for `Client.UnauthorizedOperation` errors on sensitive AWS EC2 APIs to detect persistent reconnaissance attempts.
- Ensure that CloudTrail logging is enabled and ingested into a centralized SIEM for timely correlation and triage.
