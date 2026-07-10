---
title: AWS EC2 Traffic Mirroring Abuse for Data Exfiltration
slug: 2024-01-08-aws-ec2-traffic-mirroring
description: An attacker creates an Amazon EC2 Traffic Mirroring session to capture and exfiltrate sensitive network traffic from EC2 instances, potentially including unencrypted data.
date: "2024-01-08T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - ec2
  - traffic-mirroring
  - exfiltration
vendors:
  - AWS
products:
  - EC2 Traffic Mirroring
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1020
    technique_name: Automated Exfiltration
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1074
    technique_name: Data Staged
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1040
    technique_name: Network Sniffing
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1040
    technique_name: Network Sniffing
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_TrafficMirrorSession.html
  - https://rhinosecuritylabs.com/aws/abusing-vpc-traffic-mirroring-in-aws/
rules:
  - title: AWS EC2 Traffic Mirroring Session Creation
    description: Detects the creation of an EC2 Traffic Mirroring session, which can be used for malicious traffic capture.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1040
    data_sources:
      - cloudtrail
      - aws
  - title: AWS EC2 Traffic Mirroring Target Creation
    description: Detects the creation of an EC2 Traffic Mirroring target, which could indicate preparation for malicious traffic capture.
    platform: sigma
    severity: low
    tactics:
      - exfiltration
    techniques:
      - T1040
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

Amazon EC2 Traffic Mirroring is a legitimate AWS feature used for network diagnostics and intrusion detection, but it can be abused by malicious actors to capture sensitive data. This technique involves creating a traffic mirroring session that copies network packets from a source Elastic Network Interface (ENI) to a mirror target (another ENI or Network Load Balancer).  An attacker with sufficient privileges can configure these sessions to capture network traffic, potentially unencrypted, from targeted EC2 instances.  This data can then be exfiltrated or analyzed for sensitive information, such as credentials or proprietary data. This activity is detected via AWS CloudTrail logs related to the `CreateTrafficMirrorSession` event.

## Attack Chain

1.  The attacker gains unauthorized access to an AWS account with sufficient IAM privileges to create and manage EC2 Traffic Mirroring resources.
2.  The attacker uses AWS CLI or the AWS Management Console to discover available EC2 instances and their associated ENIs using `DescribeNetworkInterfaces` and `DescribeInstances`.
3.  The attacker creates a `TrafficMirrorTarget`, specifying either another ENI (owned by the attacker) or a Network Load Balancer (NLB) as the destination for the mirrored traffic.
4.  The attacker creates a `TrafficMirrorFilter` with ingress and egress rules to capture the desired network traffic, potentially targeting specific ports or protocols.
5.  The attacker creates a `TrafficMirrorSession`, linking the source ENI, the mirror target, and the traffic mirror filter.
6.  The traffic mirroring session immediately begins copying network packets from the source ENI to the target.
7.  If the target is an ENI owned by the attacker, they can capture the mirrored traffic using tools like `tcpdump` or `Wireshark`. If the target is an NLB, the attacker controls the backend instances receiving traffic from the NLB.
8.  The attacker analyzes the captured traffic for sensitive information and exfiltrates the data to an external location.

## Impact

Successful exploitation can lead to the compromise of sensitive data, including credentials, proprietary information, and customer data.  The scope of the impact depends on the configuration of the Traffic Mirroring session and the sensitivity of the traffic being mirrored. This can affect an organization's regulatory compliance, financial standing, and reputation. The lack of encryption of mirrored traffic exacerbates the risk.

## Recommendation

*   Deploy the Sigma rule "AWS EC2 Traffic Mirroring Session Creation" to detect the creation of traffic mirroring sessions in your environment.
*   Monitor AWS CloudTrail logs for `CreateTrafficMirrorTarget`, `CreateTrafficMirrorFilter`, and `CreateTrafficMirrorFilterRule` events to detect suspicious creation or modification of traffic mirroring resources.
*   Enforce least privilege IAM policies to restrict who can create and manage EC2 Traffic Mirroring resources. Specifically, limit permissions for `ec2:CreateTrafficMirrorSession`, `ec2:CreateTrafficMirrorTarget`, and `ec2:CreateTrafficMirrorFilter`.
*   Implement AWS Service Control Policies (SCPs) or IAM conditions to limit where traffic mirroring sessions can be created (e.g., only into designated monitoring VPCs).
*   Review existing traffic mirroring configurations to ensure they are authorized and properly secured, referencing the AWS documentation on Traffic Mirroring.
*   Investigate any `CreateTrafficMirrorSession` events where the `user_agent.original` or `source.ip` is unfamiliar or unexpected.
