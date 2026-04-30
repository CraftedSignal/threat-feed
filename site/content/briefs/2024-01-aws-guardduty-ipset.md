---
title: AWS GuardDuty IP Set Manipulation for Defense Impairment
slug: 2024-01-aws-guardduty-ipset
description: An attacker modifies AWS GuardDuty IP sets, potentially whitelisting malicious IPs to disable security alerts and impair defenses.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-impairment
  - aws
vendors:
  - Amazon
products:
  - AWS GuardDuty
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/RhinoSecurityLabs/pacu/blob/866376cd711666c775bbfcde0524c817f2c5b181/pacu/modules/guardduty__whitelist_ip/main.py#L9
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_guardduty_disruption.yml
rules:
  - title: AWS GuardDuty IP Set Creation
    description: Detects creation of new IP sets in AWS GuardDuty, which could be used to whitelist malicious IPs.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
    data_sources:
      - aws
      - cloudtrail
  - title: AWS GuardDuty IP Set Activation
    description: Detects activation of an IP set in AWS GuardDuty, which could indicate an attempt to manipulate the threat intelligence used for detection.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
    data_sources:
      - aws
      - cloudtrail
rules_count: 2
---

An adversary may attempt to impair an organization's defenses by manipulating the IP sets within AWS GuardDuty. GuardDuty IP sets are used to whitelist trusted IPs or blacklist known malicious IPs. By modifying these lists, an attacker can effectively disable alerts for their malicious activity, allowing them to operate undetected within the AWS environment. This activity is typically performed after initial access and lateral movement, as the attacker seeks to maintain persistence and evade detection. The changes could be made via the AWS Management Console, CLI, or programmatically through the AWS API, making it difficult to immediately recognize the change as malicious.

## Attack Chain

1.  The attacker gains initial access to the AWS environment through compromised credentials or an exposed IAM role.
2.  The attacker enumerates existing GuardDuty IP sets using the `ListIPSets` API call to identify potential targets for modification.
3.  The attacker creates a new IP set using `CreateIPSet` API call, which contains malicious IPs they intend to whitelist, or the legitimate IPs of internal scanners they wish to mimic.
4.  GuardDuty validates the uploaded IP set list.
5.  The attacker activates the newly created IP set within GuardDuty, making it the active trusted or threat list.
6.  The attacker conducts malicious activity, such as lateral movement, data exfiltration, or resource exploitation, from the whitelisted IPs.
7.  GuardDuty, configured with the modified IP sets, does not generate alerts for activity originating from the whitelisted IPs.
8.  The attacker maintains persistence and achieves their objective (e.g., data theft, denial of service) without detection.

## Impact

A successful attack can lead to significant data breaches, resource compromise, and prolonged unauthorized access. The modification of IP sets within GuardDuty directly impairs the ability of security teams to detect and respond to ongoing threats. By whitelisting malicious IPs, attackers can bypass security controls and operate freely within the AWS environment. The number of affected organizations depends on the scope of the compromised AWS accounts and the extent to which GuardDuty is relied upon for threat detection.

## Recommendation

*   Deploy the Sigma rule "AWS GuardDuty IP Set Creation" to your SIEM to detect suspicious creation of IP sets in GuardDuty (logsource: aws, service: cloudtrail).
*   Investigate any changes to GuardDuty configurations, particularly the creation or modification of IP sets, using CloudTrail logs.
*   Implement multi-factor authentication (MFA) for all AWS accounts and IAM roles to prevent unauthorized access (related to initial access).
*   Regularly review and audit IAM roles and permissions to minimize the blast radius of compromised credentials.
