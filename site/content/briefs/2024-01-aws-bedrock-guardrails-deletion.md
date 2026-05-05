---
title: AWS Bedrock GuardRails Deletion Attempt
slug: 2024-01-aws-bedrock-guardrails-deletion
description: Detection of AWS Bedrock GuardRails deletion, which are security controls to prevent harmful AI outputs, could indicate an adversary attempting to remove safety measures after credential compromise to enable malicious model outputs.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - bedrock
  - cloudtrail
  - defense-evasion
vendors:
  - Amazon
  - Splunk
products:
  - Bedrock
  - CloudTrail
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html
  - https://docs.aws.amazon.com/bedrock/latest/APIReference/API_DeleteGuardrail.html
  - https://attack.mitre.org/techniques/T1562/
rules:
  - title: Detect AWS Bedrock GuardRails Deletion
    description: Detects attempts to delete AWS Bedrock GuardRails, which could indicate malicious activity to bypass security controls.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS Bedrock GuardRails Deletion by Unusual User Agent
    description: Detects attempts to delete AWS Bedrock GuardRails by a user agent that is not typically associated with Bedrock management.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This analytic focuses on detecting the deletion of AWS Bedrock GuardRails. AWS Bedrock is a fully managed service that offers a choice of high-performing foundation models (FMs) from leading AI companies. GuardRails within Bedrock are security controls designed to prevent harmful, biased, or inappropriate AI outputs. The deletion of these guardrails, detected through AWS CloudTrail logs, could indicate a malicious actor attempting to bypass security measures after compromising credentials. This could potentially enable harmful or malicious model outputs, leading to the generation of offensive content, extraction of sensitive information, or circumvention of prompt injection defenses. This activity matters to defenders as it highlights a potential attempt to manipulate AI model behavior for malicious purposes, requiring immediate investigation.

## Attack Chain

1.  An attacker gains unauthorized access to an AWS account with sufficient privileges to manage Bedrock resources, possibly through credential compromise.
2.  The attacker authenticates to the AWS environment, establishing a session.
3.  The attacker identifies existing AWS Bedrock GuardRails configurations using AWS APIs or the AWS Management Console.
4.  The attacker uses the `DeleteGuardrail` API call via the AWS CLI, SDK, or Management Console, specifying the `guardrailIdentifier` of the targeted GuardRail.
5.  AWS CloudTrail logs the `DeleteGuardrail` event, including details such as the user identity, source IP address, and GuardRail identifier.
6.  The GuardRail is successfully deleted, removing the configured safety controls for the Bedrock models.
7.  The attacker leverages the now-unprotected Bedrock models to generate harmful content, extract sensitive information, or bypass other security controls.
8.  The attacker exfiltrates sensitive data generated from the unprotected model to an external location.

## Impact

Successful deletion of Bedrock GuardRails could allow attackers to manipulate AI models for malicious purposes. This could lead to the generation of offensive or harmful content, extraction of sensitive information, or bypassing prompt injection defenses. Organizations utilizing AWS Bedrock may experience reputational damage, data breaches, and regulatory compliance issues. While specific victim numbers are unavailable, the impact could be significant depending on the sensitivity of the data processed by the models.

## Recommendation

*   Enable AWS CloudTrail logging for all AWS regions, specifically capturing Bedrock service events to ensure the `DeleteGuardrail` API calls are logged (data_source).
*   Deploy the provided Sigma rule `Detect AWS Bedrock GuardRails Deletion` to your SIEM and tune for your environment to detect unauthorized GuardRail deletions.
*   Investigate any detected `DeleteGuardrail` events to determine the legitimacy of the action and identify potential credential compromise or malicious intent (Sigma rule).
*   Implement an allowlist for expected administrators who regularly manage GuardRails configurations to reduce false positives (known_false_positives).
*   Monitor the `src` IP addresses from which `DeleteGuardrail` API calls are made to identify potentially suspicious or unauthorized access points (rule and RBA).
*   Enforce multi-factor authentication (MFA) for all AWS accounts, especially those with privileges to manage Bedrock resources, to mitigate credential compromise (overview).
