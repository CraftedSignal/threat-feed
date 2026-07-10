---
title: Rapid Multi-Region AWS Service Quota Enumeration for EC2 vCPU Limits
slug: 2024-11-aws-service-quotas-discovery
description: An AWS principal rapidly enumerates EC2 on-demand vCPU service quotas across multiple regions, indicative of cloud infrastructure discovery for malicious purposes such as cryptocurrency mining or botnet hosting.
date: "2024-11-14T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - aws
  - service_quotas
  - discovery
vendors:
  - AWS
products:
  - EC2
  - Service Quotas
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1526
    technique_name: Cloud Service Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
references:
  - https://www.sentinelone.com/labs/exploring-fbot-python-based-malware-targeting-cloud-and-payment-services/
  - https://docs.aws.amazon.com/servicequotas/2019-06-24/apireference/API_GetServiceQuota.html
  - https://github.com/aws-samples/aws-incident-response-playbooks/blob/c151b0dc091755fffd4d662a8f29e2f6794da52c/playbooks/
  - https://github.com/aws-samples/aws-customer-playbook-framework/tree/a8c7b313636b406a375952ac00b2d68e89a991f2/docs
  - https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/
rules:
  - title: AWS Multi-Region EC2 Service Quota Enumeration
    description: Detects rapid enumeration of EC2 service quotas across multiple AWS regions, indicating potential reconnaissance activity.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1526
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Service Quotas API Call from Unusual User Agent
    description: Detects GetServiceQuota API calls from unusual user agents, potentially indicating the use of attacker-controlled tools.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1526
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This alert identifies suspicious activity related to the enumeration of AWS service quotas. Specifically, it detects a single AWS principal making GetServiceQuota API calls for the EC2 service quota L-1216C47A (vCPU limit for on-demand EC2 instances) across more than 10 AWS regions within a 30-second window. This behavior is atypical for normal administrative tasks and is often associated with adversaries attempting to assess available compute resources for malicious activities. Such activities include cryptocurrency mining, malware hosting, or establishing command-and-control infrastructure. This detection highlights potential cloud infrastructure discovery using compromised credentials or a compromised workload. The rule was last updated on 2026-04-10.

## Attack Chain

1. An attacker gains access to an AWS account through compromised credentials or a compromised workload.
2. The attacker uses the AWS API to enumerate service quotas.
3. The attacker issues GetServiceQuota API calls.
4. The API calls specify the "ec2" service and the quota code "L-1216C47A", targeting on-demand vCPU limits.
5. These calls are made across more than 10 different AWS regions within a short time frame (30 seconds).
6. The attacker analyzes the results to identify regions with sufficient vCPU capacity for their purposes.
7. Based on discovered capacity, the attacker may proceed to launch EC2 instances for malicious activities like crypto mining.
8. The attacker deploys and executes malicious payloads on the provisioned instances.

## Impact

Compromised AWS accounts can lead to significant resource abuse and financial losses. Rapid enumeration of EC2 service quotas often precedes the deployment of compute-intensive workloads, such as cryptocurrency miners or botnet infrastructure, which can consume substantial resources and generate unexpected cloud costs. Successful exploitation can also enable the hosting of malware or the establishment of command-and-control servers, potentially impacting numerous downstream victims. While the rule has a low severity, the activity it detects may be a precursor to more serious malicious activity and should be investigated.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM and tune it for your environment to detect rapid multi-region service quota enumeration.
*   Review the `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.access_key_id` from the CloudTrail logs to identify the source of the API calls and validate its legitimacy.
*   Investigate the `source.ip`, `source.as.organization.name`, and `user_agent.original` from the CloudTrail logs to assess the origin of the requests and identify any suspicious or unexpected sources.
*   Correlate the detected activity with subsequent EC2-related actions like `RunInstances` or `CreateLaunchTemplate` in CloudTrail to identify potential resource abuse.
*   Implement tighter IAM permissions to restrict access to Service Quotas APIs where not explicitly required, as described in the AWS Knowledge Center security best practices.
