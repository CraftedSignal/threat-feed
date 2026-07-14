---
title: AWS Bedrock AgentCore Runtime Prompt Targeting Credentials or Instance Metadata
slug: 2026-07-aws-bedrock-credential-harvesting
description: This rule detects prompts sent to Amazon Bedrock AgentCore runtimes that attempt to harvest credentials or exfiltrate data by referencing cloud instance metadata services, explicit AWS access/secret keys, or combining prompt-injection/jailbreak language with intent to reveal secrets or send data to external endpoints, indicating an attempt to weaponize the agent for credential theft.
date: "2026-07-14T07:56:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud-security
  - llm
  - ai
  - prompt-injection
  - credential-access
  - data-exfiltration
vendors:
  - Amazon
products:
  - Amazon Bedrock AgentCore
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Identifies prompts... that reference the cloud instance metadata service (169.254.169.254, the ECS task metadata address, or the "latest/meta-data" / "security-credentials" paths)
    confidence_band: high
references:
  - https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/observability.html
  - https://unit42.paloaltonetworks.com/bypass-of-aws-sandbox-network-isolation-mode/
iocs:
  - type: ip
    value: 169.254.169.254
  - type: ip
    value: 169.254.170.2
ioc_counts:
  ip: 2
rules:
  - title: AWS Bedrock AgentCore Runtime Prompt Targeting Credentials or Instance Metadata
    description: Identifies prompts sent to an Amazon Bedrock AgentCore runtime that attempt to harvest credentials or coerce the agent into exfiltrating data, indicated by references to cloud instance metadata services, AWS access/secret keys, or combined prompt-injection/jailbreak language with secret-extraction/exfiltration intent.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552
      - T1552.005
    data_sources:
      - cloud
      - aws
rules_count: 1
---

This threat brief details attempts to weaponize Amazon Bedrock AgentCore runtimes for credential theft and data exfiltration. Attackers craft malicious prompts targeting the agent to either extract sensitive information directly or coerce it into revealing internal system details. The threat leverages prompt injection techniques to bypass agent guardrails and access cloud instance metadata services (IMDS), AWS access and secret keys, or to exfiltrate data to external endpoints. While the agent may refuse these requests, the very attempt is a strong indicator of malicious intent, as a misconfigured or highly capable agent could comply, leading to the compromise of AWS resources. This activity highlights the importance of securing AI agents and monitoring their interactions for suspicious prompts that could lead to credential access.

## Attack Chain

1. **Reconnaissance & Crafting**: An attacker researches AWS Bedrock AgentCore capabilities and identifies potential weaknesses for prompt injection or data exfiltration. They craft a malicious prompt designed to access sensitive information.
2. **Initial Access (Prompt Delivery)**: The attacker sends the crafted prompt to the Bedrock AgentCore runtime (e.g., via a web application frontend, API gateway, or direct `InvokeAgentRuntime` call).
3. **Instruction Injection**: The AgentCore runtime processes the prompt, which contains instructions referencing cloud instance metadata service IPs (e.g., `169.254.169.254`, `169.254.170.2`), specific metadata paths (`/latest/meta-data`, `/security-credentials`), explicit AWS access key names (`aws_secret_access_key`, `aws_access_key_id`), or a combination of "jailbreak" language (e.g., "ignore previous instructions", "developer mode") with intent to reveal system prompts, credentials, or exfiltrate data to an external URL.
4. **Agent Processing & Potential Action**: The agent attempts to interpret and act on the malicious instructions. If the agent is misconfigured, has code execution capabilities, or possesses network access to the specified endpoints, it might attempt to retrieve or generate the requested sensitive information.
5. **Exfiltration (Conditional)**: If the agent complies with the malicious prompt and has outbound network access, it might send the harvested credentials, API keys, or other sensitive data to an attacker-controlled external endpoint (e.g., `https://attacker.com/data`).
6. **Credential Acquisition & Abuse**: The attacker receives the exfiltrated credentials or sensitive data, which can then be used to gain unauthorized access to AWS resources, escalate privileges, or conduct further attacks within the cloud environment.

## Impact

Successful exploitation of an AWS Bedrock AgentCore through credential harvesting or data exfiltration can lead to severe consequences. Attackers can gain unauthorized access to AWS accounts and resources, potentially leading to data breaches, privilege escalation, resource modification or deletion, and financial losses due to unauthorized resource usage. The impact can extend across multiple services if the compromised credentials have broad permissions. Organizations using vulnerable agents could face significant reputational damage, regulatory fines, and disruption of critical business operations. Even if the agent refuses the request, the presence of such malicious prompts indicates targeted efforts to breach cloud security.

## Recommendation

* Deploy the provided Sigma rule to your SIEM and monitor for alerts on suspicious prompts targeting AWS Bedrock AgentCore.
* Ensure `aws_bedrock_agentcore.runtime_application_logs` are enabled and ingested into your security monitoring platform to capture the necessary telemetry for this detection.
* Review the full prompt in `aws.bedrock_agentcore.request_payload.prompt` for any detected incidents to confirm intent.
* Identify the agent using `aws.bedrock_agentcore.agent_name` or `aws.bedrock_agentcore.resource_arn` and the session with `aws.bedrock_agentcore.session_id` to investigate surrounding prompts.
* Verify that AgentCore guardrails are configured to block instance-metadata and credential-exfiltration prompts.
* Ensure IMDSv2 is enforced, and agent execution roles are configured with the principle of least privilege, especially if the agent has code execution or outbound network access capabilities.
