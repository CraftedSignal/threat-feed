---
title: Detecting Suspicious AWS EC2 Instance Connect SSH Key Injection
slug: 2026-10-aws-ec2-ssh-key-abuse
description: An AWS identity performing a high volume of SendSSHPublicKey API calls may indicate automated lateral movement or unauthorized access attempts via EC2 Instance Connect.
date: "2026-10-19T02:50:59Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lateral-movement
  - cloud
  - aws
  - cloudtrail
vendors:
  - Amazon
products:
  - AWS EC2 Instance Connect
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: EC2 Instance Connect temporarily makes an SSH public key available to an operating-system user on an EC2 instance.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: A burst of these calls may indicate automated attempts to establish access or move laterally using compromised AWS credentials.
    confidence_band: high
rules:
  - title: Detect AWS EC2 Multiple SSH Public Keys Uploaded by Single Identity
    description: Detects an AWS identity making 10 or more successful EC2 Instance Connect SendSSHPublicKey API calls within a short period, potentially indicating credential misuse.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.004
      - T1021.008
    data_sources:
      - cloud
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to the SIEM and tune against administrative service accounts.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic logic for CloudTrail monitoring.
  hunt_leads:
    - lead: Search for identities with high frequency of SendSSHPublicKey calls in historical CloudTrail data.
      technique_id: T1021.008
      data_needed:
        - CloudTrail logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: The analytic relies on detecting bursts of API calls.
---

This threat involves the abuse of the AWS EC2 Instance Connect service, specifically the `SendSSHPublicKey` API call. Attackers with compromised AWS credentials can use this API to temporarily push an SSH public key to an EC2 instance, granting them shell access to an operating system user without requiring long-term persistent keys. Security teams should monitor for anomalous bursts of these API calls originating from a single identity, which may signal automated lateral movement, unauthorized fleet access, or persistent probing by an attacker. Defenders should baseline expected administrative usage, as orchestration tools and automated patching workflows may trigger similar patterns.

## Impact

Successful exploitation allows an attacker to gain unauthorized remote access to EC2 instances, facilitating data exfiltration, lateral movement within the VPC, or the deployment of additional malicious tools. The primary concern is the rapid, automated nature of this technique which allows an attacker to compromise multiple targets simultaneously using a single set of compromised credentials.

## Recommendation

* Deploy detection logic to monitor AWS CloudTrail for a high volume of `SendSSHPublicKey` events from a single identity.
* Establish an allowlist for known administrative or automated deployment identities that perform legitimate fleet management.
* Audit permissions to ensure that IAM identities are restricted to only the necessary EC2 instances using condition keys (e.g., `ec2:InstanceIdentifier`).
* Investigate the `src` IP and `user_agent` associated with alerted identities to differentiate between automated management tools and unauthorized activity.
