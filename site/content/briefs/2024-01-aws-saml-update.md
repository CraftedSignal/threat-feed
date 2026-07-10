---
title: AWS SAML Identity Provider Update Detection
slug: 2024-01-aws-saml-update
description: Detection of unauthorized updates to AWS SAML identity providers using CloudTrail logs, potentially indicating compromised federated credentials and unauthorized access.
date: "2024-01-09T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - saml
  - identity-federation
  - cloud
vendors:
  - Amazon Web Services
products:
  - AWS Identity and Access Management
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://www.cisa.gov/uscert/ncas/alerts/aa21-008a
  - https://www.splunk.com/en_us/blog/security/a-golden-saml-journey-solarwinds-continued.html
  - https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf
  - https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps
rules:
  - title: AWS SAML Provider Updated
    description: Detects updates to SAML identity providers in AWS CloudTrail logs, indicating potential compromise or unauthorized access.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1078
    data_sources:
      - cloudtrail
      - aws
  - title: AWS SAML Provider Updated from Unusual Source IP
    description: Detects updates to SAML identity providers from a source IP address not normally associated with AWS administration.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - credential_access
    techniques:
      - T1071.001
      - T1078
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This brief focuses on detecting unauthorized modifications to SAML identity providers within Amazon Web Services (AWS). The technique leverages the `UpdateSAMLProvider` API call captured in AWS CloudTrail logs. Threat actors may target SAML configurations to establish persistence, bypass multi-factor authentication (MFA), and gain privileged access to cloud resources. The update of a SAML provider, when unauthorized, signifies a high-risk event, potentially leading to the compromise of federated identities and subsequent data breaches. This activity is particularly concerning given the increasing reliance on federated identity for accessing cloud environments and the potential for widespread impact following a successful breach. This brief provides detection rules and recommendations to identify and mitigate this threat.

## Attack Chain

1.  **Initial Access:** An attacker compromises an AWS account with sufficient privileges to modify SAML identity providers. This might involve exploiting a vulnerability, using stolen credentials, or through social engineering.
2.  **Privilege Escalation (If Needed):** The compromised account may require privilege escalation to gain the necessary permissions to modify the SAML provider.
3.  **Discovery:** The attacker enumerates existing SAML identity providers in the AWS environment to identify a target for modification.
4.  **Credential Access:** The attacker modifies the SAML provider configuration to inject malicious assertions or redirect authentication to an attacker-controlled endpoint (Golden SAML).
5.  **Persistence:** By modifying the SAML provider, the attacker establishes a persistent backdoor, allowing them to authenticate as any user within the federated domain.
6.  **Lateral Movement:** The attacker uses the forged SAML assertions to move laterally within the AWS environment, accessing resources and services under the guise of legitimate users.
7.  **Data Exfiltration / Impact:** The attacker accesses sensitive data, compromises critical systems, or disrupts services based on the compromised federated identities.
8.  **Covering Tracks:** The attacker may attempt to disable or modify CloudTrail logs to hide their activity.

## Impact

Successful modification of a SAML identity provider can have severe consequences, potentially affecting all users and resources that rely on the compromised provider. This can lead to unauthorized access to sensitive data, disruption of critical services, and significant financial losses. The impact can extend beyond the immediate breach, potentially affecting downstream systems and partner organizations that rely on the compromised AWS environment. The CISA alert AA21-008A highlights the risks associated with Golden SAML attacks, underscoring the importance of detecting and preventing such activity.

## Recommendation

*   Deploy the provided Sigma rule `AWS SAML Provider Updated` to detect unauthorized modifications to SAML identity providers by monitoring `UpdateSAMLProvider` events in CloudTrail logs.
*   Investigate any detected `UpdateSAMLProvider` events for unexpected source IP addresses, user agents, or IAM roles. Correlate with other security events to identify potentially compromised accounts.
*   Implement strict access controls and multi-factor authentication (MFA) for all IAM users and roles, particularly those with permissions to manage SAML identity providers.
*   Regularly review and audit SAML identity provider configurations for any unauthorized changes or suspicious activity.
*   Monitor for suspicious activity originating from the source IP addresses identified in the detection rule (`src_endpoint.ip`).
*   Enable and monitor AWS CloudTrail logs for all AWS accounts and regions to ensure comprehensive logging of API activity.
*   Use the provided drilldown searches to investigate detection results for specific users.
