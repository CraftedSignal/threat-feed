---
title: Unauthenticated MCP Servers Expose Cloud Data and Enable Command Execution
slug: 2026-07-exposed-mcp-servers
description: Unauthenticated Model Context Protocol (MCP) servers, particularly those running protocol version 2024-11-05, are widely exposed across cloud environments, enabling significant security risks by allowing attackers to bypass authentication, gain initial access, execute arbitrary commands on backend systems, obtain sensitive cloud credentials (including temporary ones via Server-Side Request Forgery against cloud metadata endpoints), discover internal systems and data, and collect/exfiltrate sensitive information like PII, business records, and security findings.
date: "2026-07-28T16:06:01Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cloud-security
  - AI
  - unauthenticated-access
  - data-exposure
  - command-execution
products:
  - Model Context Protocol (MCP) server (protocol version 2024-11-05)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: How unauthenticated Model Context Protocol (MCP) servers are opening doors to sensitive cloud data, IAM, and command execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: In some cases a tool directly runs commands or evaluates code on the server. In others, the server wraps a language-model agent that has shell access to the backend.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1526
    technique_name: Cloud Roles
    evidence: On a small but confirmed number of hosts, we reached the instance metadata service and received temporary credentials.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: A malicious call to one of these servers looks nearly identical to a legitimate one. The server makes the same backend request with the same embedded credential it always uses, and the backend answers an authorized, well-formed request without complaint. No failed login attempt, no denied-access spike indicative of a brute-force attack, and therefore no alert.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Direct secret exposure is the most straightforward class. Some tools hand back credentials or connection strings outright, with no agent or pivot needed. In one case, Lambda function logs retrieved through cloudwatch_get_lambda_logs contained environment variables with API keys. In another, a tool's response included a database connection string with embedded credentials.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: The tools/list call returns a full, machine-readable catalog of everything the server can do, with the parameter schema for each tool.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: A BI platform exposed query_sql alongside get_connection_schemas and get_connection_table_columns, letting an anonymous caller enumerate every connected database and run arbitrary queries across them.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1535
    technique_name: Unsecured Credentials
    evidence: Sensitive-data access is the most common class. Servers in this group proxy tools that reach production databases, internal mailboxes, issue trackers, and regulated records - returning real data to an anonymous caller because the backend credentials are baked into the deployment.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: Sensitive-data access is the most common class. Servers in this group proxy tools that reach production databases, internal mailboxes, issue trackers, and regulated records - returning real data to an anonymous caller.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
    evidence: 'The same agent can also be aimed at the cloud metadata endpoint: a tool that fetches a URL or proxies a request can reach internal services a caller could never access directly.'
    confidence_band: high
references:
  - https://www.wiz.io/blog/the-risk-hiding-behind-exposed-mcp-servers
---

Wiz Research has identified a critical security risk stemming from widely exposed and unauthenticated Model Context Protocol (MCP) servers across various cloud environments, including those operated by Fortune 500 companies. Despite the protocol's rapid adoption, many organizations have not implemented the security features introduced in the March 2025 specification, leaving older protocol versions (specifically 2024-11-05) vulnerable. These exposed MCP servers allow anonymous callers to access sensitive data, perform destructive write and delete operations on critical systems, and in rare but severe cases, achieve remote code execution and steal cloud credentials. The inherent design of MCP, which by default describes its capabilities, facilitates reconnaissance for attackers. Detection is challenging as malicious interactions often mimic legitimate operations, making it difficult for security teams to differentiate between authorized and unauthorized access without specific application-level logging.

## Attack Chain

1. **Reconnaissance and Discovery**: An attacker scans the internet to identify publicly accessible MCP servers.
2. **Unauthenticated Connection**: An anonymous client connects to the identified MCP server without requiring any authentication.
3. **Tool Catalog Retrieval**: The attacker sends a `tools/list` request, receiving a full, machine-readable catalog of all functionalities (tools) exposed by the server, including their descriptions and parameter schemas.
4. **Sensitive Data Access**: The attacker invokes tools that proxy sensitive data from backend systems such as production databases, internal mailboxes, issue trackers, and regulated records, leading to the exfiltration of PII, business records, or security findings.
5. **Write and Delete Operations**: The attacker utilizes tools to create, update, or delete records within critical CRM, IAM, or infrastructure backends, potentially causing data corruption or service disruption.
6. **Code Execution and Network Access**: The attacker exploits tools designed for direct command execution or leverages embedded language-model agents with shell access to the backend, using carefully crafted prompts to bypass guardrails.
7. **Credential Access via SSRF**: The attacker directs tools that fetch URLs or proxy requests towards the cloud metadata endpoint, performing Server-Side Request Forgery (SSRF) to obtain temporary cloud credentials.
8. **Secret Exposure**: The attacker directly retrieves hardcoded credentials or database connection strings that are sometimes embedded within tool responses or retrieved from logs (e.g., Lambda environment variables), leading to further compromise.

## Impact

The successful exploitation of unauthenticated MCP servers leads to severe consequences across multiple dimensions. Organizations risk exposure of highly sensitive information, including employee PII, internal business records, and detailed application security findings, which can result in data breaches and regulatory penalties. Attackers can gain the ability to perform unauthorized write and delete operations on critical systems like CRM, IAM platforms, and underlying infrastructure, potentially leading to data manipulation, account compromise, or denial of service. The most severe impact includes remote code execution on backend servers and the theft of cloud credentials, which can grant attackers pervasive access to an organization's cloud environment, facilitating lateral movement, resource manipulation, and large-scale data exfiltration. The report notes that detection is particularly difficult because unauthorized access often appears as legitimate activity due to baked-in credentials and the lack of explicit authentication failures.

## Recommendation

* **Audit MCP Servers**: Conduct a comprehensive audit to identify all Internet-reachable MCP servers and verify their authentication requirements, as described in the Wiz research.
* **Implement Authentication**: For any public-facing MCP server, enforce authentication for tool execution, even if the tool catalog remains open. Leverage the OAuth 2.1 support introduced in the March 2025 MCP specification where possible.
* **Principle of Least Privilege**: Limit the permissions of MCP servers and scope their backend credentials to the absolute minimum required for their intended function to prevent anonymous access to sensitive data or destructive actions.
* **Enable Agent Logging**: For MCP servers wrapping language-model agents, enable and capture agent prompts and invocation logs, as these are critical artifacts for detecting potential code execution or data exfiltration attempts.
