---
title: AWS IAM SAML Provider Creation for Persistence
slug: 2026-07-aws-iam-saml-provider-created
description: Adversaries with administrative access to an AWS account can create rogue SAML Identity Providers (IdPs) to establish persistent, federated access to AWS resources that survives credential rotation, enabling them to assume roles and access resources by forging SAML assertions from an IdP they control.
date: "2026-07-15T14:21:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - aws-iam
  - identity-and-access-audit
  - persistence
vendors:
  - Amazon Web Services
products:
  - AWS IAM
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Adversaries who have gained administrative access may create rogue SAML providers to establish persistent, federated access to AWS accounts that survives credential rotation.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Creating a SAML provider allows attackers to assume roles and access resources by forging SAML assertions from an IdP they control.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1484
    technique_name: Domain or Tenant Policy Modification
    evidence: Creating a SAML provider establishes a trust relationship between AWS and the external IdP.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateSAMLProvider.html
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_saml.html
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a
rules:
  - title: Detect AWS IAM SAML Provider Creation
    description: Detects the creation of a new SAML Identity Provider (IdP) in AWS IAM, which can be used by adversaries to establish persistent federated access to AWS accounts. This is a rare administrative action requiring close monitoring.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1078
      - T1078.004
      - T1098
      - T1098.001
      - T1484
      - T1484.002
    data_sources:
      - cloud
      - cloudtrail
      - aws
rules_count: 1
---

Adversaries who have successfully compromised an AWS account with administrative privileges may create new Security Assertion Markup Language (SAML) Identity Providers (IdPs) within AWS Identity and Access Management (IAM) to establish a persistent backdoor. This technique allows attackers to maintain unauthorized federated access to AWS resources, even if their initial access credentials are rotated or revoked. By controlling an external IdP, attackers can forge SAML assertions, enabling them to assume roles within the compromised AWS account and access resources without requiring traditional AWS credentials. The creation of SAML providers is an infrequent administrative action, typically reserved for initial Single Sign-On (SSO) integration or major infrastructure changes, making its unauthorized occurrence a high-fidelity indicator of potential adversarial activity. Monitoring successful `CreateSAMLProvider` API calls is crucial for detecting this form of persistence and preventing long-term unauthorized access.

## Attack Chain

1. Adversary obtains administrative access to an AWS account, typically through compromised credentials or misconfiguration exploitation.
2. The adversary executes the `CreateSAMLProvider` API call via the AWS CLI, SDK, or console to register a new SAML Identity Provider in IAM.
3. During this registration, the adversary specifies SAML metadata that points to an external IdP under their control.
4. The adversary then creates or modifies an existing IAM role, establishing a trust policy that allows the newly registered rogue SAML IdP to assume the role.
5. Using their controlled external IdP, the adversary generates and signs malicious SAML assertions.
6. The adversary presents these forged SAML assertions to AWS via the `AssumeRoleWithSAML` API call, which grants temporary credentials for the trusted IAM role.
7. With these temporary credentials, the adversary gains persistent access to AWS resources, bypassing multi-factor authentication and credential rotation mechanisms.

## Impact

Successful exploitation allows attackers to establish a covert and persistent method of access to an AWS environment. This backdoor enables them to assume various IAM roles, granting them ongoing control over cloud resources, data exfiltration capabilities, and the ability to launch further attacks. The persistence mechanism is particularly dangerous as it can survive credential rotation, making it difficult to fully evict the attacker. While specific victim counts are not available, any organization utilizing AWS IAM for identity federation is susceptible if administrative access is compromised. The financial, reputational, and operational damage can be severe, including unauthorized data modification or deletion, service disruptions, and compliance violations.

## Recommendation

* Deploy the Sigma rule "Detect AWS IAM SAML Provider Creation" to your SIEM and tune for your environment to detect `CreateSAMLProvider` API calls.
* Restrict `iam:CreateSAMLProvider` permissions to a highly limited set of administrative roles using AWS IAM policies.
* Enable AWS CloudTrail logging for all management events to capture `CreateSAMLProvider` and `AssumeRoleWithSAML` API calls.
* Implement Service Control Policies (SCPs) to control SAML provider creation in member accounts within AWS Organizations.
* Use AWS Config rules to monitor identity provider configurations for unauthorized changes.
