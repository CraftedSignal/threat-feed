---
title: AgentCore CLI Code Injection Vulnerability
slug: 2026-07-agentcore-code-injection
description: The AgentCore CLI is vulnerable to arbitrary code execution due to improper escaping of metadata when importing Amazon Bedrock agents, allowing attackers to inject malicious Python code into generated files.
date: "2026-07-29T16:11:04Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - code-injection
  - supply-chain
  - amazon-bedrock
  - cve-2026-11393
vendors:
  - Amazon
products:
  - AgentCore CLI
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: a crafted collaborationInstruction value... can terminate the string boundary and inject arbitrary Python statements into the generated source file.
    confidence_band: high
cves:
  - id: CVE-2026-11393
    cvss: 9
    epss: 0.00322
references:
  - https://github.com/advisories/GHSA-m4x6-gwgp-4pm7
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-11393
---

CVE-2026-11393 affects the Amazon AgentCore CLI (versions 0.4.0 through 0.14.1 and preview versions 0.3.0-preview.7.0 through 1.0.0-preview.8). The vulnerability exists within the 'agentcore add agent --type import' command, which improperly handles the 'collaborationInstruction' field fetched from Bedrock agent metadata. This field is interpolated into a triple-quoted string within a generated Python file (main.py). By crafting a metadata value containing triple double-quotes, an attacker can break the string boundary and inject arbitrary Python code. This vulnerability is significant because the injected code executes in the developer's local environment during development and within the AWS AgentCore Runtime environment during agent invocation, potentially compromising the AWS execution role.

## Attack Chain

1. An attacker with 'bedrock:AssociateAgentCollaborator' permissions associates a malicious collaborator agent with a target supervisor agent.
2. The attacker sets the 'collaborationInstruction' field of the collaborator metadata to a payload containing triple double-quotes followed by arbitrary Python code.
3. A developer or automated process executes 'agentcore add agent --type import' to ingest the supervisor agent configuration.
4. The AgentCore CLI fetches the metadata from the Bedrock API and injects the payload directly into the 'main.py' file.
5. The developer runs 'agentcore dev' on their local machine, triggering the execution of the injected Python code under their current local AWS credentials.
6. The developer executes 'agentcore deploy' and subsequently triggers 'agentcore invoke', causing the injected code to run in the cloud environment under the agent's IAM execution role.

## Impact

The vulnerability allows for arbitrary code execution on both local developer workstations and in the AWS runtime environment where the agent is deployed. An attacker could leverage this to steal local developer credentials or abuse the IAM execution role of the deployed Bedrock agent to perform unauthorized actions within the victim's AWS account. Any agent imported or redeployed using vulnerable CLI versions remains susceptible until the code is regenerated with a patched CLI version.

## Recommendation

1. Upgrade the AgentCore CLI to version 0.14.2 or 1.0.0-preview.9 immediately to prevent new occurrences of the injection.
2. For all previously imported agents, developers must remove the agent from the project, re-run 'agentcore add agent --type import' using the patched CLI to regenerate a clean 'main.py', and redeploy the agent to AWS.
3. Manually audit the 'main.py' files of existing imported agents for triple double-quote sequences if immediate regeneration is not possible.
4. Restrict 'bedrock:AssociateAgentCollaborator' IAM permissions to authorized users to mitigate the likelihood of malicious metadata injection.
