---
title: Unauthorized AWS Bedrock Agent Creation for Persistence
slug: 2026-10-aws-bedrock-agent-persistence
description: Adversaries with compromised human IAM credentials can create rogue Bedrock Agents to establish persistent AI-driven footholds for data exfiltration, service pivoting, or C2 signaling.
date: "2026-10-01T20:11:46Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:amazon:bedrock:*:*:*:*:*:*:*:*
tags:
  - cloud
  - bedrock
  - persistence
  - aws
  - unauthorized-ai-usage
vendors:
  - Amazon
products:
  - AWS Bedrock
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    evidence: Adversaries with access to an AWS account can create rogue agents configured to exfiltrate data via action group Lambda functions, pivot to other services, or act as a persistent AI-driven command-and-control channel.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/bedrock/latest/userguide/agents.html
  - https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_CreateAgent.html
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/persistence_bedrock_agent_created.toml
rules:
  - title: Detect Unauthorized AWS Bedrock Agent Creation by IAM User or Root
    description: Detects the creation of an Amazon Bedrock Agent performed directly by an IAM User or Root account, which is a potential indicator of persistence via rogue AI agents.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1505
    data_sources:
      - process_creation
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Cloud Security
  immediate_actions:
    - action: Deploy the provided detection rule and alert on CreateAgent events by IAM Users.
      owner: Detection Engineering
      due: 48h
      evidence: Rule ID 4e2dcdf4-f012-4b67-980b-1551b7149305
  mitigation_plan:
    - priority: immediate
      action: Restrict bedrock:CreateAgent IAM permissions to authorized service roles only.
      owner: IAM Administration
      addresses: Unauthorized Bedrock Agent creation
      evidence: Source documentation on agent security
---

Adversaries possessing compromised AWS IAM user or root account credentials can leverage Amazon Bedrock to create rogue autonomous agents. These agents serve as persistent, AI-driven footholds that operate independently of the initial compromise point. By configuring these agents with specific system instructions and malicious action groups (Lambda functions), attackers can execute multi-step tasks, query internal knowledge bases, and pivot to external services. 

Defenders must differentiate between legitimate automated deployment pipelines, which typically utilize AssumedRole sessions, and interactive creation via human IAM identities. The creation of Bedrock agents by IAM users or the root account is a high-signal indicator of potential unauthorized activity, as production infrastructure is almost exclusively managed via service-linked roles. This threat is particularly concerning because the AI agent itself acts as a persistent command-and-control channel that can perform actions autonomously over extended periods without further interaction from the adversary.

## Impact

Successful deployment of rogue Bedrock Agents grants attackers an autonomous capability to interact with cloud environments, potentially leading to unauthorized data exfiltration through Lambda-based action groups, lateral movement into internal services, and the establishment of a persistent, non-traditional C2 channel that is difficult to detect using standard network-based traffic analysis.

## Recommendation

* Deploy detection logic to monitor 'CreateAgent' API calls originating from human IAM identities (IAMUser or Root).
* Restrict the 'bedrock:CreateAgent' permission to authorized CI/CD roles using IAM policies or Service Control Policies (SCPs).
* Audit existing Bedrock agent configurations, specifically reviewing the 'instruction' system prompt and the 'actionGroupExecutor' Lambda ARNs for anomalous or unauthorized code.
* Investigate 'PrepareAgent', 'CreateAgentAlias', and 'AssociateAgentKnowledgeBase' events following any detected agent creation to determine the scope of agent deployment.
