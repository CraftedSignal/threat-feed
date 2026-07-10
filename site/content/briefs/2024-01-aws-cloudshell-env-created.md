---
title: AWS CloudShell Environment Created
slug: 2024-01-aws-cloudshell-env-created
description: The creation of a new AWS CloudShell environment is detected, potentially indicating unauthorized access for command execution within AWS by adversaries without needing local CLI credentials.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - aws
  - cloudshell
vendors:
  - AWS
products:
  - AWS CloudShell
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1059.009.html
  - https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud
rules:
  - title: AWS CloudShell Environment Created
    description: Detects the creation of a new AWS CloudShell environment.
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1059.009
    data_sources:
      - cloudtrail
      - aws
  - title: AWS CloudShell Execution via Cloud API
    description: Detects command execution via Cloud API in AWS CloudShell
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.009
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies the creation of a new AWS CloudShell environment. CloudShell is a browser-based shell providing command-line access to AWS resources directly from the AWS Management Console. The `CreateEnvironment` API is called when a user launches CloudShell for the first time or when accessing CloudShell in a new AWS region. Adversaries with console access may abuse CloudShell to execute commands, install tools, or interact with AWS services without needing local CLI credentials. This is especially useful if the attacker is already authenticated into the AWS Console. Monitoring environment creation helps detect unauthorized CloudShell usage stemming from compromised console sessions.

## Attack Chain

1. An attacker compromises AWS console credentials through methods such as phishing or credential stuffing.
2. The attacker logs into the AWS Management Console.
3. The attacker navigates to the CloudShell service.
4. The `CreateEnvironment` API is invoked as the attacker launches CloudShell for the first time in a region.
5. The attacker executes commands within the CloudShell environment to enumerate AWS resources (e.g., using `aws s3 ls`).
6. The attacker attempts to escalate privileges by exploiting misconfigurations or vulnerabilities.
7. The attacker uses CloudShell to interact with other AWS services, potentially deploying malicious infrastructure or exfiltrating data.
8. The attacker establishes persistence within the AWS environment through methods like creating new IAM users or roles with elevated permissions.

## Impact

Successful exploitation via CloudShell can lead to unauthorized access to AWS resources, data exfiltration, and deployment of malicious infrastructure. While the source material does not specify a number of victims, the impact can range from minor data breaches to significant disruptions of AWS-hosted services, depending on the permissions of the compromised account and the attacker's objectives. Even with MFA enabled, sufficiently sophisticated attackers might bypass these protections.

## Recommendation

*   Deploy the Sigma rule "AWS CloudShell Environment Created" to your SIEM using `event.dataset: "aws.cloudtrail" and event.provider: "cloudshell.amazonaws.com" and event.action: "CreateEnvironment"` to detect initial environment creation.
*   Correlate CloudShell creation events with preceding `ConsoleLogin` events by reviewing `source.ip` and `user_agent.original` to investigate session origin and login context.
*   Restrict CloudShell access using Service Control Policies (SCPs) or IAM policies for accounts that do not require it, as mentioned in the overview, to limit the attack surface.
