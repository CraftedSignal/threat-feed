---
title: Malicious Usage of AWS IMDS Credentials Outside of Expected Services
slug: 2024-07-aws-imds-abuse
description: Compromised EC2 instances may be leveraged to exfiltrate and misuse AWS Instance Metadata Service (IMDS) credentials to perform actions outside of the expected AWS Simple Systems Manager (SSM) service, indicating potential lateral movement or data exfiltration.
date: "2024-07-11T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - attack.privilege-escalation
  - attack.initial-access
  - attack.persistence
  - attack.stealth
  - attack.t1078
  - attack.t1078.002
vendors:
  - Amazon
products:
  - EC2
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-identity-roles.html
  - https://ermetic.com/blog/aws/aws-ec2-imds-what-you-need-to-know/
  - https://www.packetmischief.ca/2023/07/31/amazon-ec2-credential-exfiltration-how-it-happens-and-how-to-mitigate-it/#lifting-credentials-from-imds-this-is-why-we-cant-have-nice-things
rules:
  - title: Malicious Usage Of IMDS Credentials Outside Of AWS Infrastructure
    description: Detects when an instance identity has taken an action that isn't inside SSM, indicating a compromised EC2 instance being used as a pivot point.
    platform: sigma
    severity: high
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078
      - T1078.002
    data_sources:
      - aws
      - cloudtrail
  - title: Suspicious IAM Role Assumption Outside of SSM
    description: Detects IAM role assumption events originating from IP addresses outside the expected AWS internal range when the assumed role is associated with an EC2 instance.
    platform: sigma
    severity: medium
    tactics:
      - privilege-escalation
    techniques:
      - T1555.005
    data_sources:
      - aws
      - cloudtrail
rules_count: 2
---

This activity focuses on the potential misuse of AWS Instance Metadata Service (IMDS) credentials. When an EC2 instance is compromised, an attacker can extract the temporary credentials stored within the IMDS. These credentials, associated with an assumed role, grant the attacker the ability to interact with other AWS services. The abnormal use of these credentials outside of the expected AWS Simple Systems Manager (SSM) service may indicate malicious activity such as lateral movement, data exfiltration, or resource compromise. This is particularly concerning when the compromised instance is being used as a pivot point to access other AWS resources.

## Attack Chain

1. An EC2 instance is compromised through an initial access vector (e.g., software vulnerability, misconfiguration, or credential compromise).
2. The attacker gains access to the compromised EC2 instance's operating system.
3. The attacker queries the IMDS endpoint (http://169.254.169.254/latest/meta-data/iam/security-credentials/) to obtain temporary AWS credentials associated with the instance's IAM role.
4. The attacker configures their local AWS CLI or SDK with the exfiltrated credentials.
5. The attacker attempts to perform actions against other AWS services using the exfiltrated credentials.
6. The attacker attempts to escalate privileges or move laterally within the AWS environment.
7. The attacker attempts to access, modify, or exfiltrate sensitive data from other AWS services.
8. The attacker maintains persistence by creating new IAM users or roles with excessive permissions.

## Impact

Successful exploitation can lead to unauthorized access to sensitive data stored in AWS services such as S3, DynamoDB, and RDS. This could result in data breaches, financial loss, and reputational damage. Attackers can also leverage the compromised credentials to pivot to other AWS resources, potentially impacting critical infrastructure and services. Organizations with lax security configurations and overly permissive IAM roles are at higher risk.

## Recommendation

*   Deploy the Sigma rule "Malicious Usage Of IMDS Credentials Outside Of AWS Infrastructure" to your SIEM and tune for your environment to detect anomalous use of IMDS credentials.
*   Review and restrict IAM roles assigned to EC2 instances to follow the principle of least privilege, limiting the scope of potential damage from credential exfiltration.
*   Monitor CloudTrail logs for unusual API calls originating from EC2 instances with assumed roles, specifically those not related to SSM.
*   Harden EC2 instances to prevent initial compromise by applying security patches, configuring strong authentication, and regularly scanning for vulnerabilities.
