---
title: Abuse of AWS Bedrock AgentCore Execution Role Credentials for Cloud Privilege Escalation
slug: 2026-07-aws-bedrock-agentcore-cred-abuse
description: Anomalous AWS API calls by an Amazon Bedrock AgentCore execution role indicate potential credential exfiltration and abuse for cloud privilege escalation, lateral movement, or reconnaissance outside its intended runtime environment.
date: "2026-07-17T06:32:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud-security
  - aws
  - bedrock
  - privilege-escalation
  - credential-access
  - microvm
  - code-interpreter
vendors:
  - Amazon
products:
  - Amazon Bedrock AgentCore
  - AWS Code Interpreter
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: An AgentCore execution role suddenly calling STS, EC2, IAM, Secrets Manager, or other services is a strong indicator that the role's temporary credentials were exfiltrated from the agent's microVM ... and are being used outside the runtime for reconnaissance, privilege escalation, or lateral movement.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Public research has shown the Code Interpreter microVM exposes the execution role's temporary credentials through the instance metadata service (IMDS), and that a string-filter bypass allows exfiltrating them outside the sandbox.
    confidence_band: high
references:
  - https://sonraisecurity.com/blog/sandboxed-to-compromised-new-research-exposes-credential-exfiltration-paths-in-aws-code-interpreters/
  - https://unit42.paloaltonetworks.com/bypass-of-aws-sandbox-network-isolation-mode/
rules:
  - title: AWS Bedrock AgentCore Execution Role Used Outside Its Runtime
    description: Detects anomalous AWS API calls made by an Amazon Bedrock AgentCore execution role, indicating potential credential exfiltration and abuse for reconnaissance, privilege escalation, or lateral movement. AgentCore roles typically only interact with Bedrock inference, data-plane, and observability services.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - privilege_escalation
    techniques:
      - T1078.004
      - T1552.005
    data_sources:
      - cloudtrail
rules_count: 1
---

Attackers are exploiting vulnerabilities within AWS Code Interpreter microVMs to exfiltrate temporary credentials from Amazon Bedrock AgentCore execution roles. Normally, these roles are restricted to interacting with Bedrock inference, AgentCore data-plane, and observability services like CloudWatch Logs, X-Ray, and CloudWatch metrics. Public research highlights a string-filter bypass that allows an attacker to steal these credentials via the instance metadata service (IMDS). Once exfiltrated, these compromised credentials enable attackers to perform unauthorized AWS API calls to services such as STS, EC2, IAM, or Secrets Manager. This activity, logged under the legitimate AgentCore execution role's identity in CloudTrail, signals malicious reconnaissance, privilege escalation, or lateral movement within the AWS environment, making detection of the first anomalous service call crucial for defense.

## Attack Chain

1. An attacker compromises an Amazon Bedrock AgentCore's Code Interpreter microVM, likely by exploiting a string-filter bypass vulnerability within the sandbox environment.
2. The attacker abuses the compromised microVM's access to the instance metadata service (IMDS) to retrieve temporary AWS credentials for the AgentCore execution role.
3. The attacker successfully exfiltrates these temporary AWS credentials, associated with the AgentCore execution role, from the microVM sandbox.
4. The exfiltrated credentials are then used to make unauthorized AWS API calls to services outside the AgentCore's normal operational scope, such as `sts:GetCallerIdentity`, `ec2:Describe*`, or `iam:List*/Get*` for reconnaissance.
5. The attacker leverages these stolen credentials to attempt privilege escalation (e.g., `sts:AssumeRole`, `iam:Put*/Attach*`) or achieve lateral movement to other AWS resources and accounts.
6. The successful abuse results in unauthorized access to sensitive data, modification of AWS resources, or further deep compromise of the cloud environment.

## Impact

The successful exfiltration and abuse of AWS Bedrock AgentCore execution role credentials can lead to significant unauthorized access within an organization's AWS environment. Attackers can perform extensive reconnaissance, gain elevated privileges, and move laterally across various AWS services. This allows them to access sensitive data, modify critical configurations, deploy additional malicious resources, or disrupt operations. The compromise can impact a wide range of AWS-dependent applications and services, leading to data breaches, service outages, and potential financial and reputational damage. The broad access afforded by assumed roles means that the blast radius of such an incident can be substantial, affecting multiple cloud accounts or entire organizational infrastructure.

## Recommendation

* Deploy the Sigma rule "AWS Bedrock AgentCore Execution Role Used Outside Its Runtime" to your SIEM and tune for your environment to detect anomalous API calls.
* Review the `aws.cloudtrail.user_identity.session_context.session_issuer.arn` and `event.provider` fields for any triggered alerts and investigate the legitimacy of the activity.
* Restrict Bedrock AgentCore execution roles to the principle of least privilege, ensuring they only have access to necessary services and actions.
* Configure AWS Code Interpreter microVMs to use VPC network mode where possible and ensure the instance metadata service requires session tokens to mitigate credential exfiltration risks.
* If unauthorized activity is confirmed, immediately revoke the affected execution role's active sessions and rotate any associated secrets.
* Refer to the provided references from Sonrai Security and Palo Alto Networks Unit 42 for further details on string-filter bypasses and sandbox escapes.
