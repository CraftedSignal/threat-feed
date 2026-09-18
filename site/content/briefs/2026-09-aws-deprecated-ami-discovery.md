---
title: Detection of AWS EC2 Deprecated AMI Discovery
slug: 2026-09-aws-deprecated-ami-discovery
description: Detection of reconnaissance activity where AWS users or roles query the EC2 API for deprecated Amazon Machine Images, a technique used by adversaries to identify vulnerable or outdated system images for potential exploitation.
date: "2026-09-18T19:29:29Z"
lastmod: "2026-09-18T19:32:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud-security
  - discovery
  - aws
  - cloud
  - exfiltration
  - collection
vendors:
  - Amazon
products:
  - Amazon EC2
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
    evidence: Identifies when a user has queried for deprecated Amazon Machine Images (AMIs) in AWS.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1020
    technique_name: Automated Exfiltration
    evidence: Adversaries can abuse sessions to covertly capture and exfiltrate sensitive, potentially unencrypted, traffic.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: While used for diagnostics and NDR/IDS tooling, adversaries can abuse sessions to covertly capture and exfiltrate sensitive, potentially unencrypted, traffic.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1074
    technique_name: Data Staged
    evidence: Adversaries can abuse sessions to covertly capture and exfiltrate sensitive, potentially unencrypted, traffic from instances or subnets.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1040
    technique_name: Network Sniffing
    evidence: Detects successful creation of an Amazon EC2 Traffic Mirroring session.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ami-deprecate.html
  - https://attack.mitre.org/techniques/T1580/
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_TrafficMirrorSession.html
  - https://rhinosecuritylabs.com/aws/abusing-vpc-traffic-mirroring-in-aws/
rules:
  - title: AWS EC2 Deprecated AMI Discovery
    description: Detects when an AWS identity queries for deprecated Amazon Machine Images via the DescribeImages API call.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1580
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS EC2 Full Network Packet Capture
    description: Detects successful creation of an Amazon EC2 Traffic Mirroring session, which can be abused for covert network sniffing.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1040
      - T1537
    data_sources:
      - cloud
      - aws
rules_count: 2
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Cloud Security
  immediate_actions:
    - action: Deploy the Sigma rule to monitor for DescribeImages API calls with includeDeprecated=true
      owner: Detection Engineering
      due: 72h
      evidence: Source provides specific query parameters for detection.
  hunt_leads:
    - lead: Identify all IAM identities that have performed DescribeImages with includeDeprecated=true in the last 30 days
      technique_id: T1580
      data_needed:
        - CloudTrail logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source identifies this as a potential reconnaissance signal.
  mitigation_plan:
    - priority: medium_term
      action: Review and restrict IAM policies allowing DescribeImages
      owner: Cloud Security
      addresses: T1580
      evidence: Source recommends restricting IAM permissions to prevent unauthorized discovery.
updates:
  - at: "2026-09-18T19:32:19Z"
    level: L1
    summary: 'added detection rule: Detect AWS EC2 Full Network Packet Capture'
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/exfiltration_ec2_full_network_packet_capture_detected.toml
---

This detection brief addresses the reconnaissance technique where an AWS identity queries for deprecated Amazon Machine Images (AMIs). Attackers often perform this discovery during the post-compromise or initial access phases to identify outdated or unpatched system images that may contain known vulnerabilities. By leveraging the `DescribeImages` API call with the `includeDeprecated` parameter set to `true`, an adversary can enumerate images that are no longer recommended for use but may still be available in the environment. While these queries are not inherently malicious and can occur during legitimate maintenance or security assessments, they provide a strong signal of unauthorized discovery when originating from unexpected identities or sources. Defenders should monitor these API calls to correlate them with subsequent instance launch activity or lateral movement attempts within the AWS account.

## Impact

Successful reconnaissance of deprecated AMIs can lead to the identification of legacy systems that lack critical security patches, potentially exposing the environment to RCE or privilege escalation if an attacker manages to launch and compromise these instances. Monitoring this activity assists in reducing the attack surface by identifying images that should be decommissioned or restricted via IAM policies.

## Recommendation

* Deploy the provided detection rule to monitor CloudTrail logs for the `DescribeImages` API action with the `includeDeprecated` parameter enabled.
* Restrict IAM permissions for the `ec2:DescribeImages` action to ensure only authorized service principals and administrators can perform these lookups.
* Perform a quarterly audit of all AMIs in use within the AWS environment to identify and replace deprecated images with current, hardened versions.
* Use the `aws.cloudtrail.user_identity.arn` and `source.ip` fields to investigate the context of flagged queries, cross-referencing these with any subsequent `RunInstances` API calls.
