---
title: AWS Bedrock Claude High Risk Filesystem and Exec Tool Invocation
slug: 2026-07-aws-bedrock-high-risk-tool-invocation
description: Detection identifies anomalous or high-risk usage of filesystem and execution tools (such as bash, curl, edit, write, webfetch, grep, read, read_file) invoked by an identity through AWS Bedrock Claude, flagging suspicious activity that could indicate attempts to escalate privileges, exfiltrate data, execute unauthorized commands, or establish persistence.
date: "2026-07-07T08:12:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud-security
  - ai
  - aws
  - insider-threat
  - privilege-escalation
  - data-exfiltration
vendors:
  - AWS
products:
  - AWS Bedrock Claude
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
    evidence: bash invoked via Bedrock Claude - shell execution through AI model, Human identity invoking bash via AI model - direct shell execution risk
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: curl invoked via Bedrock Claude - network call through AI model, webfetch invoked via Bedrock Claude - remote content retrieval through AI model
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Broad filesystem and execution tool set invoked via AI model - reconnaissance pattern (grep, read, read_file)
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Broad filesystem and execution tool set invoked via AI model - reconnaissance pattern (read, read_file for data access)
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over Network Medium
    evidence: curl invoked via Bedrock Claude - network call through AI model (potential for exfiltration of collected data)
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/application/aws_bedrock_claude_high_risk_filesystem_and_exec_tool_invocation.yml
  - https://aws.amazon.com/blogs/apn/unlocking-the-power-of-splunk-with-amazon-bedrock-an-agentic-ai-approach-to-build-customized-splunk-assistants-using-bedrock-agents/
  - https://help.splunk.com/en/splunk-observability-cloud/observability-for-ai/splunk-ai-infrastructure-monitoring/set-up-ai-infrastructure-monitoring/amazon-bedrock
  - https://research.splunk.com/stories/aws_bedrock_security/
  - https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html
rules:
  - title: Detect AWS Bedrock Claude High-Risk Tool Invocation
    description: Detects identities causing AWS Bedrock Claude to invoke high-risk filesystem or execution tools such as bash, curl, edit, write, webfetch, grep, read, or read_file. This indicates anomalous behavior that could lead to privilege escalation, data exfiltration, or unauthorized command execution.
    platform: sigma
    severity: high
    tactics:
      - collection
      - command_and_control
      - discovery
      - execution
      - exfiltration
    techniques:
      - T1005
      - T1041
      - T1059.004
      - T1083
      - T1105
    data_sources:
      - cloud
      - aws
rules_count: 1
---

This threat brief details the detection of high-risk filesystem and execution tool invocations by identities interacting with AWS Bedrock Claude, a generative AI service. The activity involves the use of potentially dangerous commands such as `bash`, `curl`, `edit`, `write`, `webfetch`, `grep`, `read`, and `read_file` within the AI model's operational context. These actions, especially when combined (e.g., `bash` with `curl`, or `bash` with `write`), signal potential malicious intent, including privilege escalation, data exfiltration, unauthorized command execution, or persistence establishment. The detection aims to identify anomalous behaviors that deviate from historical baselines, highlighting a critical risk given the access and capabilities an AI model might have within an AWS environment. Such activities could severely compromise data integrity and confidentiality if exploited.

## Attack Chain

This detection describes observed high-risk behaviors that an attacker could leverage within an AWS Bedrock Claude environment, rather than a specific, fully documented attack campaign. These behaviors represent critical stages an attacker might follow:

1.  **Initial Compromise/Access**: An attacker obtains unauthorized access to an AWS identity (IAM user, assumed role, or automated process) that possesses permissions to interact with AWS Bedrock Claude.
2.  **Tool Invocation for Discovery**: The compromised identity causes Bedrock Claude to invoke filesystem tools such as `grep`, `read`, or `read_file` to perform reconnaissance and discover sensitive data or system configurations within the AI model's accessible environment.
3.  **Content Retrieval**: The identity leverages Bedrock Claude to invoke network tools like `curl` or `webfetch` to retrieve external content, which could include malicious scripts, additional tools, or specific files from external sources.
4.  **Command Execution**: The identity uses Bedrock Claude to invoke an execution tool like `bash`, enabling the execution of arbitrary commands, potentially those downloaded in the previous step, to gain further control or establish a shell.
5.  **Persistence or Data Modification**: The identity causes Claude to invoke file modification tools such as `edit` or `write` to alter system configurations, establish persistence mechanisms, or modify sensitive data.
6.  **Data Exfiltration / Impact**: Through various combinations of these tools (e.g., `read` and `curl` for data exfiltration over network, or `bash` for unauthorized system control), the attacker achieves their final objective, such as data theft, unauthorized system control, or further lateral movement within the AWS environment.

## Impact

Successful exploitation of this vector can lead to severe consequences for an organization. Attackers could escalate privileges within the AWS environment, gaining unauthorized access to sensitive data and subsequently exfiltrating it to external destinations. The ability to execute arbitrary commands or modify files through an AI model offers a novel and potentially stealthy attack path, bypassing traditional security controls. While specific victim counts are not available, any organization utilizing AWS Bedrock Claude is a potential target, and a successful compromise could result in significant data breaches, service disruption, and severe reputational damage.

## Recommendation

*   Enable AWS Bedrock model invocation logging as described in the `how_to_implement` section of the source content, ensuring Claude request/response payloads are delivered to your SIEM.
*   Ingest the Amazon Bedrock invocation logs into your Splunk environment (or equivalent SIEM) following the guidance in the Splunk Add-on for AWS (https://splunkbase.splunk.com/app/1876).
*   Deploy the provided Sigma rule "Detect AWS Bedrock Claude High-Risk Tool Invocation" to your SIEM solution and configure it for your environment.
*   Review and tune the detection with your legitimate developer activity, as noted in the `falsepositives` section, to minimize alerts from authorized users invoking shell execution, file write, or network tools through Claude as part of normal operations.
