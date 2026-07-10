---
title: AWS ECR Container Scanning Reveals Medium Severity Vulnerabilities
slug: 2024-01-aws-ecr-medium-vuln
description: AWS Elastic Container Registry (ECR) image scans reveal medium-severity vulnerabilities, potentially leading to unauthorized access and data breaches if exploited within containerized applications.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - ecr
  - container
  - vulnerability
vendors:
  - AWS
products:
  - Elastic Container Registry
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2023-1234
    cvss: 4.3
    epss: 0.00275
references:
  - https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html
rules:
  - title: AWS ECR Medium Severity Vulnerability Findings
    description: Detects medium severity vulnerability findings from AWS ECR container image scans via CloudTrail logs.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.003
    data_sources:
      - cloudtrail
      - aws
  - title: AWS ECR Vulnerability Scan Initiated by User
    description: Detects the initiation of AWS ECR vulnerability scans, providing insight into who is performing the scans.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This analytic identifies medium-severity findings from AWS Elastic Container Registry (ECR) image scans. It leverages AWS CloudTrail logs, specifically the DescribeImageScanFindings event, to detect vulnerabilities in container images within AWS environments. The activity is significant for security operations centers (SOCs) as it highlights potential security risks in containerized applications. The presence of medium severity vulnerabilities suggests that attackers could potentially exploit these weaknesses. Addressing these findings is crucial to reduce the attack surface of containerized applications and prevent potential breaches. The focus is on identifying and mitigating vulnerabilities within the AWS ECR service.

## Attack Chain

1. An attacker identifies an organization using AWS ECR to store container images.
2. The attacker scans publicly accessible ECR repositories or gains access through compromised credentials.
3. Using information gathering techniques, the attacker identifies container images with known medium-severity vulnerabilities.
4. The attacker crafts a malicious container image leveraging the identified vulnerabilities.
5. The attacker uploads the malicious container image to a compromised or vulnerable ECR repository or replaces existing images if possible.
6. The vulnerable container images are deployed into the target environment (e.g., Kubernetes cluster, ECS).
7. Upon execution, the vulnerable code within the container image allows the attacker to gain unauthorized access.
8. The attacker achieves code execution within the container environment, enabling lateral movement, data exfiltration, or other malicious activities.

## Impact

Compromised container images can lead to unauthorized access, data breaches, and further exploitation within the container environment. A successful attack targeting medium severity vulnerabilities in AWS ECR could result in data breaches, service disruption, or unauthorized resource access. The number of affected systems depends on the scope of the vulnerable container deployments. If unaddressed, these vulnerabilities can serve as entry points for broader network intrusions, impacting the overall security posture of the organization.

## Recommendation

*   Deploy the provided Sigma rule to detect medium-severity findings in AWS ECR image scans, utilizing `AWS CloudTrail DescribeImageScanFindings` events.
*   Review and remediate all findings identified by AWS ECR container scanning with `severity=MEDIUM`.
*   Implement robust access controls and monitoring for AWS ECR repositories to prevent unauthorized image uploads or modifications.
*   Regularly update container images to address known vulnerabilities and ensure the latest security patches are applied.
*   Utilize AWS CloudTrail logs and the provided search queries to investigate user activity associated with detected findings.
