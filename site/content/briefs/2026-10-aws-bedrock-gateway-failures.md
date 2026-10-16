---
title: Detecting AWS Bedrock AgentCore Gateway Probing
slug: 2026-10-aws-bedrock-gateway-failures
description: A high volume of failed tool invocations against an AWS Bedrock AgentCore Gateway may indicate an adversary attempting to discover injection points or authorization bypasses within AI agent infrastructure.
date: "2026-10-16T16:24:36Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - ai-security
  - initial-access
  - monitoring
vendors:
  - Amazon
products:
  - AWS Bedrock AgentCore
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A concentrated run of failures against one gateway can indicate an attacker probing a tool's parameter surface for an injection point.
    confidence_band: med
rules:
  - title: Detect AWS Bedrock AgentCore Gateway Tool Invocation Failure Burst
    description: Detects a burst of 10 or more failed tool invocations against a single AWS Bedrock AgentCore Gateway within a 10-minute window, which may indicate probing for injection points.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy rule and establish baseline of expected error rates for critical gateways.
      owner: Detection Engineering
      due: 72h
      evidence: Source documentation for rule 61458f1a-a6d3-4303-aa14-496c3a96971b
---

The AWS Bedrock AgentCore service manages interactions between AI agents and external tools via a Gateway. Detection engineers should be aware that a concentrated burst of failed tool invocations against a single gateway can indicate an adversary performing reconnaissance. Threat actors may probe a tool's parameter surface, testing for injection vulnerabilities, authorization bypasses, or schema weaknesses. 

It is essential to distinguish between malicious probing and legitimate operational issues. Because individual tool calls fail routinely due to transient errors or bad input, this behavior only becomes a security concern when high failure rates occur within a short time window. Furthermore, because these gateway error logs do not inherently contain caller identity, confirming the health of the downstream target is critical to separating legitimate infrastructure outages from intentional adversarial probing.

## Impact

Successful exploitation of AI agent tool invocation interfaces can lead to unauthorized code execution, sensitive data exfiltration, or the circumvention of security controls implemented within the agent's tool wrapper. If the infrastructure is compromised, attackers may leverage the agent's permissions to interact with internal APIs or databases, leading to potential data breaches or service disruption.

## Recommendation

* Deploy monitoring to capture bursts of failed tool invocations using the `aws.bedrock_agentcore.gateway.payload_object.isError` field.
* Investigate the `aws.bedrock_agentcore.gateway.payload_object` logs to review stack traces and error types, which helps differentiate between malformed input (probing) and infrastructure outages.
* Confirm gateway target health by reviewing the `aws.bedrock_agentcore.gateway.resource_arn` and correlating with recent deployment history or credential updates.
* If probing is suspected, review the agent session logs and restrict permissions for the identified gateway target to minimize potential exposure.
