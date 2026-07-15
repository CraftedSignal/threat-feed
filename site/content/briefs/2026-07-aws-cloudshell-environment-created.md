---
title: Adversaries Using AWS CloudShell Environment Creation
slug: 2026-07-aws-cloudshell-environment-created
description: Adversaries with compromised AWS console access are leveraging AWS CloudShell by triggering the CreateEnvironment API call to execute commands, install tools, and interact with AWS services without requiring local CLI credentials, enabling post-compromise actions such as data exfiltration or resource modification.
date: "2026-07-15T14:03:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - cloud
  - execution
  - initial-access
vendors:
  - Amazon Web Services
products:
  - AWS CloudShell
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: CloudShell is a browser-based shell that provides command-line access to AWS resources directly from the AWS Management Console.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Adversaries with console access may use CloudShell to execute commands... unauthorized CloudShell usage from compromised console sessions.
    confidence_band: high
references:
  - https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1059.009.html
  - https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud
rules:
  - title: AWS CloudShell Environment Created
    description: Detects the creation of a new AWS CloudShell environment, which can be leveraged by adversaries with compromised console access to execute commands and interact with AWS services. This monitors the `CreateEnvironment` API call.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059
      - T1059.009
      - T1078
      - T1078.004
    data_sources:
      - cloud
      - aws.cloudtrail
rules_count: 1
---

This threat brief describes the detection of adversaries leveraging AWS CloudShell environments after gaining unauthorized console access. AWS CloudShell, a legitimate browser-based tool providing command-line access to AWS resources, becomes a potent vector for post-compromise activity. Adversaries can initiate a CloudShell environment by making the `CreateEnvironment` API call, which occurs during initial launch or when accessing CloudShell in a new AWS region. This activity signals a high-fidelity opportunity for an attacker to execute arbitrary commands, install malicious tools, or interact with AWS services directly from the compromised console session, bypassing the need for local CLI configurations or separate credentials. Monitoring the `CreateEnvironment` API call, which the Elastic rule `AWS CloudShell Environment Created` detects, is crucial for identifying unauthorized use from compromised AWS Management Console sessions and preventing further malicious actions.

## Attack Chain

1. An adversary obtains valid AWS console credentials, often via phishing, credential stuffing, or compromise of an administrator's workstation.
2. The adversary logs into the AWS Management Console using the compromised credentials, establishing an initial access point.
3. The adversary navigates to AWS CloudShell, initiating a `CreateEnvironment` API call as they launch it for the first time or attempt to use it in a new region.
4. Within the CloudShell environment, the adversary executes reconnaissance commands to survey the environment, enumerate accessible resources, and identify potential targets.
5. The adversary downloads or installs additional tools or scripts within the CloudShell environment to facilitate further exploitation or privilege escalation.
6. The adversary utilizes CloudShell to interact with AWS services, potentially modifying configurations, creating new malicious resources, or escalating privileges.
7. The adversary attempts to exfiltrate sensitive data from S3 buckets, databases, or other storage services accessible through the compromised CloudShell session.
8. The adversary could also deploy persistent backdoors or new infrastructure (e.g., EC2 instances, Lambda functions) to maintain access to the compromised AWS environment.

## Impact

Successful exploitation of compromised AWS console access via CloudShell can lead to unauthorized execution of commands within the AWS environment, resource manipulation, data exfiltration, and the establishment of persistent access mechanisms. This can result in significant financial losses, exposure of sensitive customer or corporate data, and damage to business operations. The scope of impact is limited by the permissions associated with the compromised IAM principal. No specific victim counts or sectors were identified, but any organization utilizing AWS with compromised console access is at risk.

## Recommendation

* Deploy the Sigma rule `AWS CloudShell Environment Created` to your SIEM and tune for legitimate CloudShell usage by administrators.
* Review `aws.cloudtrail` logs for `CreateEnvironment` events, focusing on the `user.name`, `source.ip`, and `user_agent.original` fields to identify suspicious activity, particularly if it deviates from expected patterns for known administrators.
* Implement AWS IAM policies and Service Control Policies (SCPs) to restrict CloudShell access for sensitive accounts or users who do not legitimately require it, minimizing the attack surface.
* Enforce Multi-Factor Authentication (MFA) for all AWS console logins to significantly reduce the risk of console session compromise that could lead to CloudShell abuse.
* Implement session duration limits for AWS console sessions to reduce the window of opportunity for an adversary to misuse CloudShell once access is gained.
