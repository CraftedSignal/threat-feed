---
title: PraisonAI Agents SSRF Vulnerability in Web Crawl Tool
slug: 2024-01-praisonai-agents-ssrf
description: The praisonaiagents library is vulnerable to Server-Side Request Forgery (SSRF) due to missing URL validation in the `web_crawl` tool's httpx fallback, potentially allowing attackers to access internal services or cloud metadata endpoints.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - praisonai
  - ai-agent
  - cloud
vendors:
  - PraisonAI
products:
  - PraisonAI Agents
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-qq9r-63f6-v542
iocs:
  - type: url
    value: http://169.254.169.254/latest/meta-data/
  - type: url
    value: http://169.254.169.254/latest/meta-data/iam/security-credentials/
ioc_counts:
  url: 2
rules:
  - title: Detect PraisonAI Agents Web Crawl Internal IP Access
    description: Detects attempts to access internal IP addresses (RFC1918, loopback, link-local) via praisonaiagents web crawl tool.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1021.001
      - T1190
    data_sources:
      - network_connection
      - linux
  - title: Detect PraisonAI Agents Web Crawl Cloud Metadata Access
    description: Detects attempts to access cloud metadata endpoints (AWS, Azure, GCP) via praisonaiagents web crawl tool.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1021.001
      - T1190
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

The `praisonaiagents` library is susceptible to a Server-Side Request Forgery (SSRF) vulnerability within the `web_crawl` tool. This flaw exists due to the httpx fallback path in `src/praisonai-agents/praisonaiagents/tools/web_crawl_tools.py:133-180` failing to validate user-supplied URLs. This allows a malicious actor to potentially trick an LLM agent into crawling internal URLs and accessing sensitive resources like cloud metadata endpoints (e.g., `169.254.169.254`), internal services, or the localhost environment. The response content is then returned to the agent and may appear in output visible to the attacker. The vulnerability is exploitable when the `TAVILY_API_KEY` is not set and the `crawl4ai` package is not installed, which is the default state after a fresh installation using `pip install praisonai`. The affected package versions are >= 0.13.23 and < 1.5.128.

## Attack Chain

1.  Attacker crafts a malicious prompt or injects it into a publicly accessible webpage.
2.  The agent processes the prompt containing instructions to visit a specific URL using the `web_crawl` tool.
3.  If `TAVILY_API_KEY` is not set and `crawl4ai` is not installed, the httpx fallback path in `web_crawl_tools.py` is triggered.
4.  The httpx client makes a GET request to the attacker-controlled URL without proper validation, including internal IP addresses.
5.  The request is sent to an internal resource, such as the cloud metadata endpoint (`169.254.169.254`).
6.  The internal service responds with sensitive information, such as IAM credentials or internal service details.
7.  The response is returned to the agent, which parses and includes the sensitive information in its output.
8.  The attacker receives the agent's output, gaining access to the exfiltrated sensitive information.

## Impact

Successful exploitation of this SSRF vulnerability can have severe consequences. On cloud infrastructure utilizing IMDSv1, attackers can obtain IAM credentials from the metadata service, potentially leading to complete compromise of the affected instance and broader access to cloud resources. In other deployments, attackers can access internal services reachable from the host, potentially revealing sensitive data or enabling further lateral movement within the network. There is no need to authenticate, the attacker just needs the agent to process input that triggers a `web_crawl` call to an internal address.

## Recommendation

*   Apply the provided remediation patch to `src/praisonai-agents/praisonaiagents/tools/web_crawl_tools.py` to implement URL validation before the httpx request (see Remediation section in content).
*   Deploy the Sigma rule "Detect PraisonAI Agents Web Crawl Internal IP Access" to identify attempts to access internal IP addresses via the vulnerable `web_crawl` tool.
*   If feasible, configure either a `TAVILY_API_KEY` or install the `crawl4ai` package to avoid triggering the vulnerable httpx fallback path.
*   Monitor network connections originating from the `praisonaiagents` application for connections to internal IP ranges, as indicated by the IOCs, using network connection logs.
