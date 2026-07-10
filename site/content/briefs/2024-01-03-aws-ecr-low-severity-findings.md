---
title: AWS ECR Container Scanning Reveals Low Severity Vulnerabilities
slug: 2024-01-03-aws-ecr-low-severity-findings
description: This analytic identifies low, informational, or unknown severity findings from AWS Elastic Container Registry (ECR) image scans using AWS CloudTrail logs, indicating potential vulnerabilities or misconfigurations in container images that could lead to unauthorized access or data breaches.
date: "2024-01-03T15:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - ecr
  - container
  - vulnerability
vendors:
  - AWS
products:
  - Elastic Container Registry
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2023-54321
    cvss: 5.5
    epss: 0.00025
references:
  - https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html
rules:
  - title: Detect AWS ECR Low Severity Findings
    description: Detects low, informational, or unknown severity findings from AWS Elastic Container Registry (ECR) image scans.
    platform: sigma
    severity: medium
    techniques:
      - T1204.003
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS ECR Container Scanning Findings - Missing Scan
    description: Detects when ECR container scanning is not enabled or not running as expected.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This threat brief addresses the risk associated with low severity findings identified during AWS Elastic Container Registry (ECR) image scans. The focus is on detecting these findings through AWS CloudTrail logs, specifically using the `DescribeImageScanFindings` event. While individually low severity, the accumulation of these vulnerabilities or misconfigurations can create attack pathways or be chained together for greater impact. Defenders need to identify and remediate these issues promptly to prevent potential exploitation. This activity helps in early identification of potential vulnerabilities or misconfigurations in container images, which could be exploited if left unaddressed. If confirmed malicious, these findings could lead to unauthorized access, data breaches, or further exploitation within the containerized environment. The scope of targeting focuses on organizations utilizing AWS ECR for container image storage.

## Attack Chain

1.  A developer introduces a container image into the AWS ECR, potentially containing low severity vulnerabilities due to outdated packages or misconfigurations.
2.  AWS ECR automatically scans the image for vulnerabilities upon creation or via scheduled scans using the `DescribeImageScanFindings` event in CloudTrail.
3.  The scan identifies low, informational, or unknown severity findings, which are logged in CloudTrail.
4.  An attacker identifies these vulnerabilities through public sources or by gaining access to internal reports/dashboards, which are based on the AWS CloudTrail logs.
5.  The attacker chains together multiple low severity vulnerabilities or combines them with other weaknesses in the application or infrastructure.
6.  The attacker exploits these vulnerabilities to gain unauthorized access to the container or the underlying host.
7.  The attacker uses this initial access to escalate privileges within the environment.
8.  The attacker moves laterally to access sensitive data or systems, ultimately achieving their objective, such as data exfiltration or disruption of services.

## Impact

While individual low severity findings might seem insignificant, their accumulation or combination with other vulnerabilities can create a significant attack surface. Successful exploitation could lead to unauthorized access to containerized applications and data, potentially impacting confidentiality, integrity, and availability. The number of affected victims is highly variable depending on the scope and severity of the vulnerabilities and the overall security posture of the organization. Targeted sectors include any organization using AWS ECR to store and manage container images.

## Recommendation

*   Deploy the provided Sigma rule `Detect AWS ECR Low Severity Findings` to your SIEM and tune it to your environment to detect the described activity.
*   Investigate any findings identified by the Sigma rule `Detect AWS ECR Low Severity Findings` to determine their potential impact and prioritize remediation.
*   Implement a vulnerability management program to regularly scan container images for vulnerabilities and track remediation efforts as documented in the references.
*   Review and harden container deployment configurations to minimize the attack surface, including limiting privileges and enabling network segmentation.
