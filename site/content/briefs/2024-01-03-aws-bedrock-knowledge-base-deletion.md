---
title: AWS Bedrock Knowledge Base Deletion Attempt
slug: 2024-01-03-aws-bedrock-knowledge-base-deletion
description: An adversary may delete AWS Bedrock Knowledge Bases, which are resources that store and manage domain-specific information for AI models, to disrupt business operations or remove traces of data access by using the DeleteKnowledgeBase API call.
date: "2024-01-03T17:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - bedrock
  - knowledge_base
  - deletion
  - cloudtrail
vendors:
  - AWS
products:
  - AWS Bedrock
  - AWS Bedrock Knowledge Base
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://www.sumologic.com/blog/defenders-guide-to-aws-bedrock/
  - https://attack.mitre.org/techniques/T1562/
rules:
  - title: Detect AWS Bedrock Knowledge Base Deletion
    description: Detects attempts to delete AWS Bedrock Knowledge Bases by monitoring AWS CloudTrail logs for DeleteKnowledgeBase API calls.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS Bedrock Knowledge Base Deletion by Unusual User Agent
    description: Detects attempts to delete AWS Bedrock Knowledge Bases by monitoring AWS CloudTrail logs for DeleteKnowledgeBase API calls with unusual user agents.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This threat brief focuses on the detection of attempts to delete AWS Bedrock Knowledge Bases, which are crucial resources for storing and managing domain-specific information used by AI models within the AWS ecosystem. The deletion of these knowledge bases is detected by monitoring AWS CloudTrail logs for DeleteKnowledgeBase API calls. This activity could signal a malicious actor who has compromised AWS credentials and is attempting to disrupt operations, conceal data access, or degrade AI capabilities. A successful deletion could severely impact model performance and remove critical business context, potentially leading to significant operational disruptions. This analytic specifically looks for the "DeleteKnowledgeBase" event within CloudTrail logs related to the "bedrock.amazonaws.com" service.

## Attack Chain

1. **Initial Access:** The attacker gains unauthorized access to an AWS account, potentially through compromised credentials or exploiting a vulnerability in the AWS environment. (T1078)
2. **Privilege Escalation:** The attacker escalates privileges within the AWS account to gain sufficient permissions to manage Bedrock Knowledge Bases. (T1068)
3. **Discovery:** The attacker uses AWS APIs or the AWS Management Console to identify existing Bedrock Knowledge Bases within the compromised account. (T1082)
4. **Credential Access:** The attacker leverages compromised credentials or obtains additional AWS credentials to perform actions in AWS Bedrock. (TA0006)
5. **Impair Defenses:** The attacker disables or modifies CloudTrail logging to prevent detection of their activities. (T1562)
6. **Resource Manipulation:** The attacker executes the `DeleteKnowledgeBase` API call, targeting specific Knowledge Base IDs to remove them from the AWS environment. (T1485)
7. **Impact:** The deletion of the Knowledge Base leads to disruption of AI models relying on the knowledge base, data loss, or degradation of AI-driven services.

## Impact

The successful deletion of AWS Bedrock Knowledge Bases can lead to significant disruptions. AI models that rely on the deleted knowledge bases may experience degraded performance or complete failure, impacting business operations. The loss of critical business context stored within these knowledge bases can also hinder decision-making processes and lead to financial losses. The number of victims and the specific sectors targeted would depend on the scope of the compromised AWS account and the usage of Bedrock services.

## Recommendation

*   Enable and monitor AWS CloudTrail logs with specific focus on Bedrock service events, especially the `DeleteKnowledgeBase` event (AWS CloudTrail).
*   Deploy the Sigma rule `Detect AWS Bedrock Knowledge Base Deletion` to your SIEM and tune it for your environment.
*   Implement multi-factor authentication (MFA) for all AWS accounts to mitigate credential compromise (T1199).
*   Review and restrict IAM permissions to limit access to sensitive AWS resources, including Bedrock Knowledge Bases (T1078).
*   Investigate any detected `DeleteKnowledgeBase` API calls originating from unfamiliar or suspicious sources (Sigma Rule, AWS CloudTrail).
*   Implement an allowlist for expected administrators who regularly manage Knowledge Base configurations and tune the provided detections based on your specific environment (Known False Positives).
