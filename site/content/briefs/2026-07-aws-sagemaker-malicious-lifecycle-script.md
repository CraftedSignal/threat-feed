---
title: AWS SageMaker Notebook Lifecycle Configuration With Suspicious Script Content
slug: 2026-07-aws-sagemaker-malicious-lifecycle-script
description: This brief details how attackers can leverage compromised AWS credentials to inject malicious, base64-encoded scripts into Amazon SageMaker notebook lifecycle configurations, which then execute as root on notebook instances, enabling persistence, credential theft, or further compromise of the AWS environment.
date: "2026-07-03T15:40:50Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - sagemaker
  - persistence
  - execution
  - backdoor
  - credential-theft
vendors:
  - Amazon
products:
  - Amazon SageMaker
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: A lifecycle configuration runs as root on the notebook instance, so a script with these patterns is a strong indicator of an attempt to backdoor the notebook, steal the execution role's credentials, or establish persistent code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: 'This rule base64-decodes the OnStart/OnCreate script from the request [...] and flags high-signal indicators across several categories: reverse shells (''/dev/tcp/'', ''bash -i'', ''nc -e'', ''ncat'', ''socat'', ''mkfifo''), IMDS credential access (''169.254.169.254'', ''/latest/meta-data/''), download-and-execute (''| sh'', ''| bash'', ''base64 -d'').'
    confidence_band: high
references:
  - https://docs.aws.amazon.com/sagemaker/latest/dg/notebook-lifecycle-config.html
---

This threat involves the abuse of Amazon SageMaker notebook lifecycle configurations by attackers to establish persistence, steal credentials, or execute arbitrary code within an AWS environment. Lifecycle configurations, specifically their OnStart or OnCreate scripts, run with root privileges on SageMaker notebook instances. Attackers who have gained initial access to an AWS account and possess sufficient IAM permissions can inject malicious scripts, often base64 encoded to evade detection, into these configurations. Upon the start or creation of a SageMaker notebook instance linked to such a configuration, the script automatically executes, allowing the adversary to perform actions like setting up reverse shells, exfiltrating EC2 instance metadata credentials, creating new persistence mechanisms via `crontab` or `authorized_keys`, or deploying cryptominers. This activity is a strong indicator of post-compromise activity and a high-fidelity signal for an active implant attempt.

## Attack Chain

1.  **Initial Access**: An attacker obtains valid AWS credentials for an account, possibly through phishing, exposed access keys, or compromise of another service.
2.  **Discovery & Privilege Escalation**: The attacker identifies that the compromised credentials possess permissions to create or update Amazon SageMaker Notebook Lifecycle Configurations (e.g., `sagemaker:CreateNotebookInstanceLifecycleConfig`, `sagemaker:UpdateNotebookInstanceLifecycleConfig`).
3.  **Malicious Configuration Creation/Update**: The attacker uses these permissions to either create a new SageMaker notebook lifecycle configuration or modify an existing one.
4.  **Script Injection**: A malicious shell script is injected into the `OnStart` or `OnCreate` section of the lifecycle configuration. This script often includes commands for reverse shells, credential exfiltration (e.g., from IMDS endpoint `169.254.169.254`), or persistence, and is frequently base64 encoded to obfuscate its content.
5.  **Deployment**: The attacker then associates this malicious lifecycle configuration with a SageMaker notebook instance.
6.  **Execution on Instance Start/Create**: When the affected SageMaker notebook instance is subsequently started or newly created, the injected `OnStart` or `OnCreate` script automatically executes with `root` privileges.
7.  **Post-Execution Activities**: The executed script performs its malicious payload, such as establishing a persistent reverse shell connection, gathering temporary AWS credentials from the EC2 Instance Metadata Service (IMDS), configuring cron jobs, modifying SSH `authorized_keys`, or deploying cryptomining software.
8.  **Impact**: The attacker gains persistent code execution capabilities, potentially exfiltrates sensitive AWS credentials, or further compromises the AWS environment, leading to data theft or resource abuse.

## Impact

If this attack succeeds, the impact can be severe, leading to unauthorized access, data exfiltration, and resource abuse within the compromised AWS environment. Attackers gain `root` access to SageMaker notebook instances, enabling them to steal sensitive data, pivot to other AWS services using compromised execution role credentials, or establish long-term persistence within the organization's cloud infrastructure. This can result in significant financial losses due to resource misuse (e.g., cryptomining), reputational damage, and regulatory penalties. The scope of victims could include any organization utilizing Amazon SageMaker that has an AWS account vulnerable to credential compromise or misconfigured IAM policies.

## Recommendation

*   Deploy the provided ESQL detection logic (FROM logs-aws.cloudtrail-... `RLIKE` ".*(/dev/tcp/|/dev/udp/|bash -i|...").
*   Review the `Esql_priv.aws_cloudtrail_lifecycle_script` field for any suspicious patterns or decoded content when this rule alerts.
*   Investigate the principal identified in `aws.cloudtrail.user_identity.arn` and correlate with `source.ip` and `user_agent.original` to determine if the activity was from an expected location or user.
*   If unauthorized, immediately remove the affected lifecycle configuration and stop any SageMaker notebook instances associated with it.
*   Rotate the credentials for the notebook execution role and any IAM principal identified in `aws.cloudtrail.user_identity.arn` that performed the suspicious action.
*   Implement strong IAM policies to restrict `sagemaker:CreateNotebookInstanceLifecycleConfig` and `sagemaker:UpdateNotebookInstanceLifecycleConfig` permissions to only trusted administrators.
