---
title: AWS Lambda Function Invoked from Unusual Source ASN
slug: 2026-07-aws-lambda-unusual-asn
description: Attackers are abusing stolen AWS execution-role or user credentials to invoke AWS Lambda functions from unusual source networks (ASNs) not previously associated with the legitimate principal, indicating a credential compromise leading to potential unauthorized access or data exfiltration.
date: "2026-07-03T15:58:16Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - cloud
  - credential-theft
  - execution
  - lambda
vendors:
  - Amazon Web Services
products:
  - AWS Lambda
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1648
    technique_name: Serverless Execution
    evidence: Lambda execution-role credentials and user credentials are frequently abused after theft... When such credentials are replayed from attacker infrastructure, the resulting direct Invoke calls originate from a network the legitimate principal has not used.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/lambda/latest/api/API_Invoke.html
  - https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html
rules:
  - title: AWS Lambda Direct Invocation from Non-Major Cloud ASN
    description: Detects direct invocations of AWS Lambda functions originating from an Autonomous System Number (ASN) that does not belong to major cloud providers (Amazon, Google, Microsoft). This detection is a component of identifying unusual invocation behavior after potential credential theft.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1648
    data_sources:
      - cloud
      - aws
rules_count: 1
---

Organizations are facing a persistent threat where malicious actors compromise AWS credentials, specifically execution-role or user credentials, to gain unauthorized access and execute functions within a victim's AWS environment. This activity is detected when an AWS Lambda function is directly invoked by a principal from an Autonomous System Number (ASN) that has not been observed for that principal within the last 10 days, excluding well-known cloud provider networks like Amazon, Google, or Microsoft. Such "out-of-pattern" invocations are a strong indicator that stolen credentials have been replayed from attacker-controlled infrastructure. The underlying credential theft might stem from various sources, including Server-Side Request Forgery (SSRF) or Remote Code Execution (RCE) vulnerabilities exploited within existing functions or other AWS resources, or simply leaked access keys. Successful exploitation can lead to data exfiltration, resource manipulation, or further lateral movement within the compromised AWS account.

## Attack Chain

1.  **Initial Access**: Attacker gains an initial foothold within the victim's environment, potentially via phishing campaigns targeting AWS users, exploitation of a public-facing application vulnerability (e.g., SSRF or RCE on an EC2 instance), or discovery of exposed AWS access keys.
2.  **Credential Theft**: Within the compromised environment, the attacker discovers and steals valid AWS credentials, which could include IAM user access keys, temporary session tokens, or execution role credentials associated with a compromised instance or service.
3.  **Lateral Movement to Attacker Infrastructure**: The attacker then transfers these stolen AWS credentials to their own command-and-control (C2) infrastructure, typically a VPS or server operating outside of the victim's legitimate network space.
4.  **Malicious Lambda Invocation**: From their controlled infrastructure, the attacker uses the stolen credentials to directly invoke an AWS Lambda function within the victim's account. This invocation originates from a source IP address and its corresponding ASN that is unusual and not historically associated with the legitimate principal.
5.  **Execution of Malicious Logic**: The invoked AWS Lambda function executes, leveraging its assigned permissions to perform unauthorized actions such as accessing sensitive data, modifying AWS resources, or triggering other services.
6.  **Data Exfiltration or Persistence**: The attacker uses the Lambda function's capabilities to exfiltrate sensitive data from the AWS environment or to establish additional persistence mechanisms for future access.

## Impact

The primary impact of such credential abuse and unauthorized Lambda invocation is the potential for significant data exfiltration, leading to regulatory penalties, reputational damage, and loss of competitive advantage. Attackers can also use the compromised Lambda function to manipulate cloud resources, escalate privileges, or deploy further malicious payloads, resulting in widespread disruption of services, increased operational costs, and a broader compromise of the AWS account. The compromise of a critical function could also lead to denial of service or integrity violations of applications.

## Recommendation

*   Enable AWS Lambda data event logging for all critical Lambda functions within CloudTrail, as this rule relies on these logs for detection.
*   Deploy the provided Sigma rule to your SIEM and tune it by adding legitimate, new source ASNs or user identities to an exclusion list after validation to reduce false positives.
*   Review `source.ip`, `source.as.organization.name`, `source.geo`, and `aws.cloudtrail.user_identity.arn` fields from reported alerts to verify legitimate operational activity.
*   Rotate or revoke any AWS credentials (`aws.cloudtrail.user_identity.access_key_id`) confirmed to be abused and review the access history of the invoked function.
*   Implement IAM conditions to constrain `lambda:InvokeFunction` permissions to expected identities and known networks where feasible.
