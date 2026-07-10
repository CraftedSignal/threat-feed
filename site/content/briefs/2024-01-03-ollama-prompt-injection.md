---
title: Ollama API Prompt Injection and Jailbreak Attempts
slug: 2024-01-03-ollama-prompt-injection
description: Detects potential prompt injection and jailbreak attempts against Ollama API endpoints by identifying requests with abnormally long response times, indicative of attackers crafting complex prompts to bypass AI safety controls.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ollama
  - prompt-injection
  - jailbreak
  - ai-security
vendors:
  - Ollama
products:
  - Ollama
references:
  - https://github.com/rosplk/ta-ollama
  - https://github.com/OWASP/www-project-ai-testing-guide
rules:
  - title: Ollama Suspicious Long Request
    description: Detects Ollama API requests with abnormally long response times, potentially indicating prompt injection or jailbreak attempts.
    platform: sigma
    severity: high
    techniques:
      - T1059
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 1
---

This threat brief focuses on detecting prompt injection and jailbreak attempts targeting Ollama, an open-source framework for running large language models (LLMs) locally. Attackers are increasingly targeting LLMs with crafted prompts designed to bypass safety controls, extract sensitive information, or manipulate model behavior. This is achieved by injecting malicious instructions into user queries, leading to unintended or harmful outputs. The detection identifies suspicious activity against Ollama API endpoints (/api/generate and /v1/chat/completions) by monitoring response times. Requests exceeding 30 seconds, coupled with high request frequency, may indicate a sophisticated jailbreak attempt, multi-stage prompt injection, or extraction of sensitive data from the model. Defenders should be aware of this emerging threat to maintain the integrity and security of their LLM deployments. The provided Sigma rules and recommendations enable proactive monitoring and alerting for these types of attacks.

## Attack Chain

1.  Attacker identifies an Ollama instance exposed via API endpoints such as `/api/generate` or `/v1/chat/completions`.
2.  The attacker crafts a malicious prompt designed to bypass safety filters or extract sensitive information (prompt injection).
3.  The attacker sends the crafted prompt to the Ollama API endpoint via an HTTP POST request.
4.  The Ollama server processes the complex prompt, leading to extended processing times.
5.  The server logs the request details, including the URI path, source IP, HTTP method, response code, and response time.
6.  A successful jailbreak or prompt injection may allow the attacker to extract internal data, manipulate model behavior, or bypass security controls.
7.  The attacker repeats the process, refining the prompt based on previous responses.
8.  The attacker potentially leverages the compromised Ollama instance for further malicious activities.

## Impact

Successful prompt injection attacks against Ollama instances can lead to several critical impacts. Attackers may be able to extract sensitive data, manipulate the model to generate harmful or biased content, or bypass security controls designed to prevent misuse. While the specific number of victims is unknown, the increasing adoption of LLMs makes this a significant concern for organizations across various sectors. If successful, these attacks can compromise data confidentiality, integrity, and availability, leading to reputational damage and financial losses.

## Recommendation

*   Deploy the Sigma rule `Ollama Suspicious Long Request` to detect abnormally long response times indicative of prompt injection attempts. Enable Ollama server logging to capture the required data (response times, URI paths, source IPs) and configure Splunk TA-ollama to ingest the logs (sourcetype: `ollama:server`).
*   Investigate alerts triggered by the `Ollama Suspicious Long Request` rule, focusing on the source IP address (`src`) and the requested URI (`uri_path`) to understand the nature of the interaction with the Ollama API.
*   Implement rate limiting and input validation on Ollama API endpoints to mitigate the risk of prompt injection attacks.
*   Regularly review and update Ollama's safety filters and security configurations to address emerging prompt injection techniques.
*   Monitor `status_code` values in the logs for unusual HTTP response codes that might indicate errors or vulnerabilities being exploited during prompt processing.
