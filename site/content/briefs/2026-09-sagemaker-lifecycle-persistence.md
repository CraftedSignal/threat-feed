---
title: Suspicious Script Injection in AWS SageMaker Lifecycle Configurations
slug: 2026-09-sagemaker-lifecycle-persistence
description: Threat actors are targeting AWS SageMaker notebook lifecycle configurations to achieve persistent, root-level code execution by injecting malicious scripts that trigger automatically upon instance startup.
date: "2026-09-18T19:41:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - persistence
  - execution
vendors:
  - Amazon
products:
  - SageMaker
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: A SageMaker notebook lifecycle configuration is a shell script that runs as root on the notebook instance at create or start.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This rule base64-decodes the OnStart/OnCreate script from the request and flags high-signal indicators... including reverse shells.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/sagemaker/latest/dg/notebook-lifecycle-config.html
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/persistence_sagemaker_lifecycle_config_suspicious_script_content.toml
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy ES query to detect suspicious content in SageMaker lifecycle configurations
      owner: Detection Engineering
      due: 48h
      evidence: Source detection rule definition
  mitigation_plan:
    - priority: immediate
      action: Restrict IAM permissions for sagemaker:CreateNotebookInstanceLifecycleConfig and sagemaker:UpdateNotebookInstanceLifecycleConfig
      owner: IT Operations
      addresses: Persistence and Execution TTPs
      evidence: Source response and remediation guide
---

Security teams should be aware of a persistent threat vector targeting AWS SageMaker notebook instances, where attackers modify lifecycle configurations to execute arbitrary code. SageMaker allows administrators to define 'OnCreate' and 'OnStart' scripts that run with root privileges whenever an instance is provisioned or launched. Attackers leverage the 'CreateNotebookInstanceLifecycleConfig' or 'UpdateNotebookInstanceLifecycleConfig' API actions to inject base64-encoded shell scripts. 

These scripts, once decoded, often contain high-signal indicators of malicious intent, including reverse shell commands (e.g., using '/dev/tcp', 'nc -e', or 'socat'), unauthorized access to the Instance Metadata Service (IMDS) at '169.254.169.254' to steal credentials, or 'download-and-execute' patterns to fetch secondary malware. Because these configurations run as root on the notebook instance, a successful injection provides the attacker with immediate, elevated persistence and the ability to pivot within the AWS environment using the notebook's associated IAM execution role. This activity is critical for detection engineering as it represents a direct abuse of legitimate infrastructure management APIs to establish a persistent foothold.

## Attack Chain

1. Attacker obtains valid AWS IAM credentials with permissions to modify SageMaker configurations (e.g., 'sagemaker:UpdateNotebookInstanceLifecycleConfig').
2. Attacker crafts a malicious script containing shell commands for persistence or credential theft.
3. Attacker base64-encodes the script content to bypass simple string-based inspection.
4. Attacker invokes the 'UpdateNotebookInstanceLifecycleConfig' API, supplying the encoded payload within the lifecycle configuration parameters.
5. AWS CloudTrail logs the API call, capturing the request parameters, including the base64-encoded script.
6. The target SageMaker notebook instance is started or created, triggering the 'OnStart' or 'OnCreate' script execution with root privileges.
7. The script executes the embedded malicious payload, establishing a reverse shell, exfiltrating IAM credentials, or downloading additional tools.
8. Attacker achieves persistent access to the notebook environment and uses the execution role's credentials for broader cloud reconnaissance or impact.

## Impact

Successful exploitation allows attackers to bypass notebook instance security controls, gain persistent root-level access, and exfiltrate sensitive cloud credentials. If the execution role assigned to the SageMaker notebook has broad IAM permissions, the attacker can leverage these credentials to escalate privileges, access other AWS services, or exfiltrate data stored in S3 or other connected resources.

## Recommendation

Prioritize monitoring of SageMaker configuration changes and implement automated analysis of lifecycle scripts.

* Deploy the provided ESQL detection rule to your SIEM/data platform to identify base64-encoded payloads containing high-signal malicious indicators.
* Enable AWS CloudTrail logging for all SageMaker API actions, specifically 'CreateNotebookInstanceLifecycleConfig' and 'UpdateNotebookInstanceLifecycleConfig'.
* Audit current lifecycle configurations to ensure they only contain approved, business-critical automation scripts.
* Enforce least-privilege IAM policies, restricting 'sagemaker:CreateNotebookInstanceLifecycleConfig' and 'sagemaker:UpdateNotebookInstanceLifecycleConfig' to a small group of authorized administrators.
* Review IAM roles attached to SageMaker notebooks and minimize the scope of their permissions to prevent lateral movement following a compromise.
