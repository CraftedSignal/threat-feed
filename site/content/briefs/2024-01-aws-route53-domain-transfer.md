---
title: AWS Route 53 Domain Transferred to Another Account
slug: 2024-01-aws-route53-domain-transfer
description: An AWS Route 53 domain was transferred to another AWS account, potentially leading to unauthorized control over DNS records and traffic redirection for malicious purposes, such as phishing or establishing persistence.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - route53
  - domain-transfer
  - persistence
  - resource-development
vendors:
  - AWS
products:
  - Route 53
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1584
    technique_name: Compromise Infrastructure
references:
  - https://docs.aws.amazon.com/Route53/latest/APIReference/API_Operations_Amazon_Route_53.html
  - https://github.com/aws-samples/aws-incident-response-playbooks/blob/c151b0dc091755fffd4d662a8f29e2f6794da52c/playbooks/
  - https://github.com/aws-samples/aws-customer-playbook-framework/tree/a8c7b313636b406a375952ac00b2d68e89a991f2/docs
  - https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/
rules:
  - title: AWS Route 53 Domain Transferred to Another Account
    description: Detects when an AWS Route 53 domain is transferred to another AWS account.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - resource_development
    techniques:
      - T1098
      - T1584
      - T1584.001
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Route 53 Disable Domain Transfer Lock
    description: Detects when the domain transfer lock is disabled on a Route 53 domain, which is often a precursor to a domain transfer.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - resource_development
    techniques:
      - T1098
      - T1584
      - T1584.001
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This threat brief addresses the unauthorized transfer of an AWS Route 53 domain to another AWS account. Route 53 is a scalable DNS web service, and control over a domain allows an attacker to modify DNS records, reroute traffic, and request certificates. The adversary could gain control by compromising an IAM user or leveraging long-lived credentials. Such a transfer can lead to persistence, traffic redirection, phishing attacks, or the staging of infrastructure for more extensive malicious operations. This activity is detected via CloudTrail logs when the `TransferDomainToAnotherAwsAccount` event is successfully invoked.

## Attack Chain

1.  An attacker gains unauthorized access to an AWS account through compromised credentials or IAM role exploitation.
2.  The attacker identifies a target domain within the Route 53 service.
3.  The attacker may disable the domain transfer lock using `DisableDomainTransferLock`.
4.  The attacker initiates a domain transfer to an AWS account under their control using the `TransferDomainToAnotherAwsAccount` API call.
5.  The transfer is successful, granting the attacker administrative control over the domain's DNS records.
6.  The attacker modifies DNS records to redirect traffic to malicious servers they control.
7.  The attacker sets up phishing sites or redirects legitimate traffic to a command-and-control infrastructure.

## Impact

A successful Route 53 domain transfer enables an attacker to fully manage the domain's DNS resources, potentially leading to traffic redirection, service outages, or domain hijacking for phishing or command-and-control. While the exact number of victims and sectors targeted is unknown, unauthorized domain transfers can severely impact any organization relying on AWS for DNS services. This could disrupt service availability, compromise sensitive data through phishing, or enable persistent access to internal networks.

## Recommendation

*   Deploy the Sigma rule `AWS Route 53 Domain Transferred to Another Account` to detect successful `TransferDomainToAnotherAwsAccount` events in AWS CloudTrail logs.
*   Monitor AWS CloudTrail logs for `DisableDomainTransferLock` events followed by `TransferDomainToAnotherAwsAccount` as it indicates a possible domain transfer preparation.
*   Restrict domain transfer permissions to a minimal set of roles using IAM Conditions such as `aws:PrincipalArn` and `aws:MultiFactorAuthPresent` as recommended in the [AWS Knowledge Center – Security Best Practices](https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/).
*   Implement change-management tracking for domain ownership modifications, correlating with approved internal requests as noted in the overview.
