---
title: Multiple Safety-Control Bypasses in @zereight/mcp-gitlab
slug: 2026-09-mcp-gitlab-bypass
description: Multiple vulnerabilities in the @zereight/mcp-gitlab package allow attackers to bypass read-only mode, exfiltrate data, perform unauthorized GitLab operations, and trigger a denial-of-service via unauthenticated session exhaustion.
date: "2026-09-16T01:05:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - mcp
  - gitlab
  - llm-security
  - supply-chain
vendors:
  - zereight
products:
  - '@zereight/mcp-gitlab (< 2.1.30)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The source describes the use of prompt injection as a vector for steering the agent, which may be initiated via external content or manipulated inputs.
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The execute_graphql tool can be used to execute arbitrary GitLab API mutations in a read-only environment.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated attacker can deny service by flooding the session slots.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: The service attaches the server's live session to upstream requests, allowing an unauthenticated attacker to use the server's GitLab credentials.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-5648-rgj9-v224
action_plan:
  priority: elevated
  owners:
    - SOC
    - DevOps
  immediate_actions:
    - action: Upgrade @zereight/mcp-gitlab to 2.1.30 or later
      owner: DevOps
      due: 24h
      evidence: Source identifies 2.1.30 as the fixed version.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to the MCP server endpoint
      owner: DevOps
      addresses: F2, F3 (unauthenticated access)
      evidence: Source notes that unauthenticated transports and missing Host validation expose the service to local network/DNS rebinding attacks.
---

The @zereight/mcp-gitlab package (version < 2.1.30) contains multiple high-severity security defects that defeat the tool's intended safety controls. The package is designed to expose GitLab functionality to LLM agents using read-only mode, project allow-lists, and transport authentication. A source review identified five critical flaws: a GraphQL query parser bypass that allows write operations in read-only mode and ignores project allow-lists; flawed authentication gates that allow unauthenticated access when specific flags are enabled; missing Origin/Host validation making the service susceptible to DNS rebinding; an unauthenticated session-exhaustion denial-of-service (DoS) vulnerability; and the verbatim exposure of CI job traces to LLMs. These vulnerabilities allow malicious clients or prompt-injected LLM agents to execute arbitrary write commands on GitLab, impersonate the server's session, or disrupt service availability.

## Attack Chain

1. An attacker identifies a target running a vulnerable instance of @zereight/mcp-gitlab on a local or accessible network.
2. The attacker exploits missing DNS rebinding protections (F3) by hosting a malicious website that performs a DNS rebind to access the local MCP service.
3. The attacker bypasses authentication (F2) due to the flawed authentication gate logic, allowing interaction with the MCP service without valid credentials.
4. The attacker sends a crafted GraphQL request through the `execute_graphql` tool.
5. The attacker prepends a comma to the GraphQL document (e.g., `,mutation{...}`) to bypass the flawed `graphqlQueryContainsWriteOperation` check (F1).
6. The service executes the mutation against the connected GitLab instance, ignoring intended read-only and project-scope restrictions.
7. The attacker repeats unauthorized `initialize` requests with garbage tokens to exhaust session slots, resulting in a DoS (F4).

## Impact

Successful exploitation allows for arbitrary unauthorized write operations on GitLab projects, potentially leading to data manipulation or destruction. By leveraging the server's live session, an attacker can access sensitive information, perform repository changes, or interact with CI/CD pipelines outside the intended scope. The unauthenticated DoS vulnerability enables service disruption with minimal request volume, effectively disabling the LLM agent integration.

## Recommendation

Prioritized actions for security teams:
- Immediately upgrade @zereight/mcp-gitlab to version 2.1.30 or later to patch the identified safety control bypasses and DoS conditions.
- Implement network-level access controls to restrict access to the MCP server to authorized users or service identities, mitigating the risks posed by the unauthenticated transport and DNS rebinding vulnerabilities (F2/F3).
- Review and harden GitLab project-level permissions to ensure that the token used by the MCP server follows the principle of least privilege, limiting the blast radius of any successful GraphQL injection (F1).
- Configure the MCP service to use a strictly defined SSE_AUTH_TOKEN and disable remote access unless explicitly required and secured by robust reverse-proxy authentication (F3).
