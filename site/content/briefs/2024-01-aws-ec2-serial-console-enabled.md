---
title: AWS EC2 Serial Console Access Enabled
slug: 2024-01-aws-ec2-serial-console-enabled
description: The EC2 Serial Console provides direct, text-based access to an instance's serial port, bypassing the network layer, which adversaries may enable for out-of-band communication, evading network-based security monitoring, firewalls, and VPC controls.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - cloudtrail
  - defense-evasion
  - ec2
vendors:
  - Amazon Web Services
products:
  - AWS EC2
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_EnableSerialConsoleAccess.html
  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-serial-console.html
  - https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud
rules:
  - title: AWS EC2 Serial Console Access Enabled
    description: Detects when EC2 Serial Console Access is enabled for an AWS account, potentially indicating an attempt to establish an out-of-band access channel.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1578.005
    data_sources:
      - cloudtrail
      - aws
  - title: AWS EC2 Serial Console SSH Key Upload
    description: Detects the SendSerialConsoleSSHPublicKey API call, indicating usage of the serial console with an uploaded SSH key.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1578.005
    data_sources:
      - cloudtrail
      - aws
  - title: AWS EC2 Get Serial Console Access Status
    description: Detects the GetSerialConsoleAccessStatus API call, which is used to check if the serial console access is enabled or disabled.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1578.005
    data_sources:
      - cloudtrail
      - aws
rules_count: 3
---

The EC2 Serial Console provides direct access to an instance's serial port, bypassing network controls. Enabling this feature at the AWS account level is required before it can be used on individual instances. While useful for troubleshooting, enabling serial console access in production is rare and can be exploited by adversaries to establish an out-of-band communication channel, bypassing network-based security monitoring. An adversary might enable the serial console to gain persistent backdoor access or interact with compromised instances without triggering standard network-based detections. This brief focuses on detecting the `EnableSerialConsoleAccess` API call, indicating potential malicious enablement of this feature. This rule detects successful `EnableSerialConsoleAccess` API calls, which may indicate an adversary attempting to establish an out-of-band access channel.

## Attack Chain

1. An adversary gains initial access to an AWS account through compromised credentials or other means (T1566).
2. The adversary attempts to disable or modify existing security tools or configurations to evade detection (T1562.001).
3. The adversary calls the `EnableSerialConsoleAccess` API to enable serial console access at the account level (T1578.005).
4. The adversary uses the `SendSerialConsoleSSHPublicKey` API to upload an SSH key for authentication.
5. The adversary establishes a serial console session with a compromised EC2 instance (T1021.002).
6. The adversary uses the serial console to interact with the instance, potentially escalating privileges or accessing sensitive data (T1068).
7. The adversary may use the compromised instance as a pivot point for lateral movement within the AWS environment (T1021.006).
8. The ultimate objective might be data exfiltration, deploying ransomware, or establishing long-term persistence (TA0005).

## Impact

Successful exploitation allows attackers to bypass network security controls, potentially leading to unauthorized access, privilege escalation, and data exfiltration. The number of victims depends on the scope of the compromised AWS environment. If successful, attackers could gain full control over EC2 instances, modify configurations, or exfiltrate sensitive data, impacting confidentiality, integrity, and availability.

## Recommendation

*   Deploy the Sigma rule `AWS EC2 Serial Console Access Enabled` to your SIEM and tune for your environment. This rule detects the `EnableSerialConsoleAccess` API call, indicating potential malicious enablement (see `rules` section).
*   Restrict `ec2:EnableSerialConsoleAccess` permissions to a limited set of administrative roles. Use IAM policies to enforce this restriction and regularly audit IAM configurations.
*   Monitor CloudTrail logs for all serial console-related API calls (`EnableSerialConsoleAccess`, `DisableSerialConsoleAccess`, `SendSerialConsoleSSHPublicKey`, `GetSerialConsoleAccessStatus`) and correlate with other suspicious activities (see `references` section).
