---
title: AWS STS GetFederationToken with AdministratorAccess in Request
slug: 2024-01-aws-sts-admin-access
description: Detection of AWS STS GetFederationToken calls with AdministratorAccess in the request parameters, indicating potential privilege escalation or dangerous automation via broadly privileged temporary credentials.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - privilege-escalation
  - lateral-movement
  - sts
  - getfederationtoken
vendors:
  - Amazon
products:
  - AWS STS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://docs.aws.amazon.com/STS/latest/APIReference/API_GetFederationToken.html
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_request.html
  - https://attack.mitre.org/techniques/T1548/
  - https://attack.mitre.org/techniques/T1548/005/
  - https://attack.mitre.org/tactics/TA0004/
  - https://attack.mitre.org/techniques/T1550/
  - https://attack.mitre.org/techniques/T1550/001/
  - https://attack.mitre.org/tactics/TA0008/
rules:
  - title: AWS STS GetFederationToken with AdministratorAccess in Request
    description: Detects successful calls to AWS STS GetFederationToken where request parameters reference AdministratorAccess, potentially indicating privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
      - privilege_escalation
    techniques:
      - T1548.005
      - T1550.001
    data_sources:
      - cloudtrail
      - aws
  - title: AWS STS GetFederationToken Called with IAM User Credentials
    description: Detects calls to AWS STS GetFederationToken using long-term IAM user credentials, as opposed to temporary role credentials.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1548.005
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

The AWS Security Token Service (STS) GetFederationToken API allows for the creation of temporary security credentials for federated users. These credentials inherit permissions from the calling IAM user and any session policy included in the request. This detection focuses on instances where the request parameters of GetFederationToken reference AdministratorAccess, either directly or through an equivalent string. The inclusion of AdministratorAccess within the session policy grants overly broad privileges to the temporary credentials, potentially leading to privilege escalation or abuse. This scenario is often indicative of legacy systems, misconfigured tooling, or malicious intent, posing a significant risk to the security posture of AWS environments. Defenders should prioritize identifying and mitigating instances of this behavior to enforce least privilege principles and prevent unauthorized access.

## Attack Chain

1. An attacker gains initial access to an AWS account, potentially through compromised IAM user credentials or an exploited vulnerability.
2. The attacker identifies an IAM user with the necessary permissions to call the STS GetFederationToken API.
3. The attacker crafts a GetFederationToken API request, including a session policy that directly references "AdministratorAccess" or includes a policy ARN that grants administrator privileges.
4. The GetFederationToken API call is successfully executed, generating temporary security credentials with broad administrator permissions.
5. The attacker uses the temporary credentials to perform privileged actions within the AWS environment, such as modifying IAM policies, accessing sensitive data, or deploying malicious resources.
6. The attacker may attempt to laterally move within the AWS environment by leveraging the newly acquired administrator privileges to compromise other resources or accounts.
7. The attacker could establish persistence by creating new IAM users or roles with elevated permissions, ensuring continued access even after the temporary credentials expire.
8. The attacker achieves their final objective, which could include data exfiltration, service disruption, or financial gain.

## Impact

Successful exploitation can lead to complete compromise of the AWS environment. An attacker with temporary administrator credentials can modify security configurations, access sensitive data, and disrupt critical services. While no specific victim counts or sectors are mentioned, the broad permissions granted by AdministratorAccess make any AWS environment vulnerable to significant damage. The risk score of 73 highlights the potential for severe impact.

## Recommendation

*   Deploy the Sigma rule "AWS STS GetFederationToken with AdministratorAccess in Request" to your SIEM to detect instances of this activity (rule title).
*   Investigate any alerts generated by the Sigma rule, focusing on the `aws.cloudtrail.request_parameters` to identify the specific policy being used (rule title).
*   Revoke or rotate the IAM user access keys involved in the GetFederationToken call and enforce least privilege on the user (rule description).
*   Monitor CloudTrail logs for subsequent events using `response_elements.credentials.accessKeyId` from the same response to identify actions taken with the temporary credentials (rule description).
*   Review and update IAM policies to ensure that session policies used with GetFederationToken adhere to the principle of least privilege (rule description).
*   Implement automated checks to prevent the creation or modification of IAM policies that grant AdministratorAccess except in explicitly approved scenarios (rule description).
