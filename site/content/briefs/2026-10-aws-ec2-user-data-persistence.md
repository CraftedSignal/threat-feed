---
title: AWS EC2 User Data Modification on Stopped Instances
slug: 2026-10-aws-ec2-user-data-persistence
description: Threat actors may stop an AWS EC2 instance and modify its user-data attribute to establish persistence or execute unauthorized code upon the next system startup.
date: "2026-10-19T02:51:06Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - execution
  - cloud
vendors:
  - Amazon
products:
  - Amazon EC2
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
    evidence: A successful EC2 StopInstances request was followed within one hour by a successful ModifyInstanceAttribute request targeting userData on the same instance, by the same IAM principal.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html
  - https://stratus-red-team.cloud/attack-techniques/AWS/aws.execution.ec2-user-data/
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: IAM principals performing StopInstances followed by ModifyInstanceAttribute (userData) on the same instance
      technique_id: T1578.005
      data_needed:
        - AWS CloudTrail
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: A successful EC2 StopInstances request was followed within one hour by a successful ModifyInstanceAttribute request targeting userData.
  mitigation_plan:
    - priority: medium_term
      action: Restrict IAM policy access for ec2:ModifyInstanceAttribute
      owner: IT Operations
      addresses: T1578.005
      evidence: Principle of least privilege.
---

Attackers may target Amazon EC2 instances by stopping a running instance and modifying its User Data attribute. By injecting custom shell scripts into this attribute, an attacker ensures that their malicious code executes with root privileges upon the next instance start. This technique is often used to establish persistence or facilitate further lateral movement within a cloud environment. Defenders should monitor for sequential IAM activities where the same principal performs a 'StopInstances' operation followed closely by a 'ModifyInstanceAttribute' call specifically targeting the 'userData' field on the same EC2 instance. This activity is significant as it leverages standard AWS management features to bypass traditional endpoint security controls by subverting the instance boot process.

## Attack Chain

1. Attacker obtains valid AWS IAM credentials with sufficient permissions to manage EC2 instances (ec2:StopInstances, ec2:ModifyInstanceAttribute).
2. Attacker enumerates target EC2 instances to identify high-value systems.
3. Attacker executes 'StopInstances' via the AWS API to transition the target instance to a stopped state.
4. Attacker waits for the instance state to change to 'stopped'.
5. Attacker executes 'ModifyInstanceAttribute' targeting the 'userData' attribute of the specific instance.
6. Attacker embeds a malicious payload, such as a reverse shell or script to download secondary malware, into the 'userData' field.
7. Attacker executes 'StartInstances' to restart the instance.
8. Instance executes the modified 'userData' script during the initialization sequence, leading to unauthorized code execution and persistence.

## Impact

Successful exploitation allows for persistent unauthorized code execution on EC2 instances. This technique can lead to full system compromise, credential harvesting, or lateral movement into the VPC, impacting organizational cloud security and compliance posture.

## Recommendation

- Deploy detection logic to identify the sequence of 'StopInstances' followed by 'ModifyInstanceAttribute' on the same instance ID by the same principal within a one-hour window.
- Implement IAM policies that follow the principle of least privilege, restricting 'ec2:ModifyInstanceAttribute' permissions to only necessary service accounts.
- Audit existing EC2 instances for unusual 'userData' configurations, particularly those that include base64-encoded scripts.
- Establish alerting for high-privileged IAM identities performing instance state management outside of documented maintenance windows.
