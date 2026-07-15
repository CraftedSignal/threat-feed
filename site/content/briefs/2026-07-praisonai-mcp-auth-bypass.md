---
title: PraisonAI MCP HTTP-Stream Authentication Bypass (CVE-2026-61427)
slug: 2026-07-praisonai-mcp-auth-bypass
description: PraisonAI versions prior to 4.6.78 contain an authentication bypass vulnerability, CVE-2026-61427, in the MCP HTTP-stream transport, allowing unauthenticated clients to establish sessions, enumerate tools, and invoke tools, potentially leading to remote code execution if the server is bound to a network-accessible address.
date: "2026-07-15T12:27:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - remote-code-execution
  - web-vulnerability
  - ai-ml
  - network
vendors:
  - PraisonAI
products:
  - PraisonAI < 4.6.78
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: 'PraisonAI before 4.6.78 exposes the MCP HTTP-stream transport without authentication by default: ... an unauthenticated client ... can initialize a session'
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: an unauthenticated client ... can enumerate the available tools (tools/list)
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: an unauthenticated client ... can invoke tools (tools/call). Additionally, the dispatcher forwards tool-call arguments to handlers without validating them against the advertised inputSchema.
    confidence_band: high
cves:
  - id: CVE-2026-61427
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61427
rules:
  - title: Detects CVE-2026-61427 Exploitation - Unauthenticated PraisonAI MCP Tool Access
    description: Detects exploitation attempts of CVE-2026-61427, an authentication bypass in PraisonAI's MCP HTTP-stream transport, by identifying unauthenticated requests to the '/tools/list' or '/tools/call' endpoints.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - execution
      - initial_access
    techniques:
      - T1059
      - T1082
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-61427 identifies a critical authentication bypass vulnerability in PraisonAI's MCP HTTP-stream transport, affecting all versions prior to 4.6.78. This flaw stems from the default configuration where the CLI `--api-key` option is set to `None`, effectively disabling Authorization/Bearer checks by the server. Consequently, an unauthenticated client can initiate a session, enumerate all available tools via the `tools/list` endpoint, and invoke these tools using the `tools/call` endpoint. The vulnerability is further exacerbated by the dispatcher's failure to validate tool-call arguments against their advertised `inputSchema`, potentially opening doors for command injection or other malicious input. While PraisonAI typically binds to `127.0.0.1` by default, remote exploitation becomes possible if an operator explicitly configures the server to listen on a network-accessible address, such as `0.0.0.0`. This vulnerability poses a significant risk as it allows unauthorized control over PraisonAI instances, leading to potential data exfiltration, system compromise, or service disruption.

## Attack Chain

1. **Reconnaissance & Target Identification**: An attacker identifies PraisonAI instances running the MCP HTTP-stream transport (e.g., `praisonai mcp serve --transport http-stream`) and determines if they are externally accessible (bound to `0.0.0.0` or a public IP address).
2. **Unauthenticated Session Establishment**: The attacker sends an HTTP request to the vulnerable PraisonAI server without an `Authorization` header to establish an unauthenticated session, taking advantage of the default `None` API key configuration.
3. **Tool Enumeration**: The unauthenticated client then sends an HTTP GET or POST request to the `/tools/list` endpoint to discover and enumerate all available tools and their functionalities.
4. **Tool Invocation**: Based on the enumerated tools, the attacker crafts an HTTP POST request to the `/tools/call` endpoint, specifying a tool and its arguments to execute a desired function on the PraisonAI instance.
5. **Argument Manipulation**: The attacker includes malicious or unvalidated arguments in the `tools/call` request, exploiting the dispatcher's failure to validate inputs against the `inputSchema`.
6. **Remote Code Execution / Impact**: Successful exploitation of unvalidated arguments through a vulnerable tool handler could lead to remote code execution, unauthorized data access, system configuration changes, or other severe impacts on the underlying host or integrated systems.

## Impact

The successful exploitation of CVE-2026-61427 grants unauthenticated attackers the ability to execute arbitrary tools on a PraisonAI instance. This can lead to unauthorized information disclosure through tool enumeration, data manipulation or deletion via tool invocation, and potentially remote code execution (RCE) if the invoked tools accept unvalidated arguments and execute them in a privileged context. The CVSS v3.1 Base Score of 7.3 indicates a high severity vulnerability. If a PraisonAI server is configured to be publicly accessible, organizations face a direct threat of system compromise, intellectual property theft, or disruption of AI/ML services by external malicious actors.

## Recommendation

* **Patch CVE-2026-61427**: Immediately upgrade PraisonAI instances to version 4.6.78 or later to address the authentication bypass vulnerability.
* **Restrict Network Binding**: Ensure PraisonAI's MCP HTTP-stream transport is not bound to a network-accessible address (e.g., `--host 0.0.0.0`) unless absolutely necessary and protected by additional network-level access controls.
* **Implement Authentication**: Configure a robust API key for PraisonAI instances to ensure `Authorization/Bearer` checks are enforced by the server.
* **Deploy the Sigma rule**: Deploy the provided Sigma rule to your SIEM to detect unauthenticated access attempts to PraisonAI's `tools/list` and `tools/call` endpoints.
* **Enable Webserver Logging**: Ensure detailed web server access logs are enabled and collected for the PraisonAI application to facilitate detection and incident response.
