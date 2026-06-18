---
title: 'PraisonAI: Server-Side Request Forgery (SSRF) in SearxNG / search_web Tools via Attacker-Controlled searxng_url Parameter'
slug: 2026-06-praisonai-ssrf
description: A Server-Side Request Forgery (SSRF) vulnerability in PraisonAI's `praisonaiagents` package (versions prior to 1.6.61), specifically within the `searxng_search` and `search_web` tools, allows an attacker to exploit prompt injection by controlling the `searxng_url` parameter, enabling the server to make requests to arbitrary internal endpoints, read responses, perform network enumeration, and potentially expose cloud instance credentials.
date: "2026-06-18T14:56:56Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - ssrf
  - llm-agent
  - prompt-injection
  - praisonai
  - python
  - ghsa
vendors:
  - PraisonAI
products:
  - praisonaiagents (< 1.6.61)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploitation of Remote Services
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1599
    technique_name: Application Layer Protocol
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1090
    technique_name: ""
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: ""
references:
  - https://github.com/advisories/GHSA-4pcv-mg8v-vrgf
iocs:
  - type: ip
    value: 169.254.169.254
ioc_counts:
  ip: 1
rules:
  - title: Detect Outbound PraisonAI Connections to Internal/Metadata IPs
    description: Detects outbound network connections initiated by the PraisonAI agent process to common internal IP ranges or cloud metadata service IP, indicative of SSRF exploitation via the searxng_url parameter.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - discovery
    techniques:
      - T1046
      - T1090.001
      - T1552.001
    data_sources:
      - network_connection
      - linux
  - title: Detect PraisonAI Agent Process Execution with Suspicious Command Line Arguments
    description: Detects the execution of PraisonAI agent processes with command line arguments that could indicate an attempt to bypass security or load untrusted configurations, though the primary vector is prompt injection.
    platform: sigma
    severity: informational
    tactics:
      - execution
    techniques:
      - T1059.006
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A significant Server-Side Request Forgery (SSRF) vulnerability has been identified in PraisonAI's `praisonaiagents` package, affecting versions prior to 1.6.61. This flaw stems from a lack of validation on the `searxng_url` parameter within the `searxng_search` and `search_web` tools, which are part of the default agent toolset. Attackers can leverage prompt injection techniques to manipulate the `searxng_url` parameter, forcing the agent's underlying `requests.get()` function to make unvalidated HTTP requests to internal systems. This allows for reading responses from internal services and APIs, performing internal network enumeration, and potentially accessing cloud instance metadata endpoints (e.g., 169.254.169.254) to expose sensitive IAM credentials or other system information. The vulnerability does not require misconfiguration and is directly exploitable through attacker-controlled content ingested by the agent.

## Attack Chain

1.  **Attacker Crafts Malicious Content**: An attacker embeds a carefully constructed prompt into content (e.g., a web page, file, or chat message) that an `praisonaiagents` LLM agent is likely to ingest.
2.  **Agent Ingests Malicious Prompt**: The `praisonaiagents` LLM agent processes the attacker-controlled content, which includes instructions designed to coerce it into calling its `search_web` or `searxng_search` tool.
3.  **Agent Calls Tool with Malicious Parameter**: Triggered by the prompt, the agent invokes `search_web(...)` or `searxng_search(...)`, passing an attacker-specified internal URL (e.g., `http://127.0.0.1:19998/admin/secrets` or `http://169.254.169.254/latest/meta-data/`) as the `searxng_url` parameter.
4.  **Unvalidated HTTP Request Made**: The Python code within `src/praisonai-agents/praisonaiagents/tools/searxng_tools.py` or `src/praisonai-agents/praisonaiagents/tools/web_search.py` receives the `searxng_url` and uses it directly in `requests.get()` without any scheme, host, or port validation.
5.  **Server Performs Internal Request**: The server hosting the `praisonaiagents` instance attempts to connect to the specified internal endpoint, effectively turning the agent into a proxy for the attacker.
6.  **Internal Response Captured and Returned**: If the internal endpoint responds, its HTTP response body is captured by the agent tool, parsed (specifically for a JSON `results` key), and returned into the agent's context.
7.  **Data Exfiltration/Enumeration**: The attacker can then coerce the agent (via further prompt injection or subsequent tool calls) to exfiltrate the captured internal data or to continue enumerating internal services based on error responses from closed ports.
8.  **Credential Exposure**: In cloud environments, successful access to the instance metadata endpoint (`169.254.169.254`) can lead to the exposure of IAM role credentials, allowing for further compromise of cloud resources.

## Impact

This SSRF vulnerability significantly compromises the security of `praisonaiagents` deployments. Any agent configured with the default `search_web` tool and capable of ingesting untrusted content (such as browsing the web, reading files, or processing external messages) is at risk. Attackers can gain unauthorized access to internal services and APIs, potentially reading sensitive data from administration panels or internal microservices that return JSON. The ability to distinguish between open and closed internal ports allows for comprehensive internal network enumeration, mapping out the internal infrastructure. Crucially, the reachability of cloud instance metadata endpoints (e.g., AWS IMDS) presents a high risk of IAM credential theft, which could lead to full compromise of the cloud environment. There are no known instances of active exploitation in the wild, but the existence of a public PoC increases the likelihood of future attacks.

## Recommendation

*   **Patch `praisonaiagents` immediately**: Upgrade the `praisonaiagents` package to version 1.6.61 or later to remediate CVE-2026-XXXX.
*   **Deploy Sigma rules**: Implement the provided Sigma rules (`Detect Outbound PraisonAI Connections to Internal/Metadata IPs` and `Detect PraisonAI Process Execution`) into your SIEM to identify suspicious activity.
*   **Implement egress filtering**: Configure network egress filtering at the host or network perimeter to block `praisonaiagents` processes from initiating connections to RFC1918 private IP ranges and the cloud instance metadata IP `169.254.169.254`.
*   **Monitor outbound network connections**: Enable detailed logging for all outbound network connections from systems running `praisonaiagents` to detect anomalous destinations, especially the IP address `169.254.169.254`.
