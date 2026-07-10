---
title: Malware Leveraging Large Language Model Endpoints for Command and Control
slug: 2024-01-llm-command-control
description: This rule detects DNS queries to known Large Language Model (LLM) domains originating from unsigned binaries or common Windows scripting utilities, indicating potential malware command and control activity.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command_and_control
  - llm
  - malware
  - windows
  - macos
vendors:
  - OpenAI
  - Anthropic
products:
  - Large Language Model services
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1102
    technique_name: Web Service
references:
  - https://malpedia.caad.fkie.fraunhofer.de/details/py.lamehug
iocs:
  - type: domain
    value: api.openai.com
  - type: domain
    value: '*.openai.azure.com'
  - type: domain
    value: api.anthropic.com
  - type: domain
    value: api.mistral.ai
  - type: domain
    value: api.cohere.ai
  - type: domain
    value: api.ai21.com
  - type: domain
    value: api.groq.com
  - type: domain
    value: api.perplexity.ai
  - type: domain
    value: api.x.ai
  - type: domain
    value: api.deepseek.com
  - type: domain
    value: api.gemini.google.com
  - type: domain
    value: generativelanguage.googleapis.com
  - type: domain
    value: api.azure.com
  - type: domain
    value: api.bedrock.aws
  - type: domain
    value: bedrock-runtime.amazonaws.com
  - type: domain
    value: api-inference.huggingface.co
  - type: domain
    value: inference-endpoint.huggingface.cloud
  - type: domain
    value: '*.hf.space'
  - type: domain
    value: '*.replicate.com'
  - type: domain
    value: api.replicate.com
  - type: domain
    value: api.runpod.ai
  - type: domain
    value: '*.runpod.io'
  - type: domain
    value: api.modal.com
  - type: domain
    value: '*.forefront.ai'
  - type: domain
    value: chat.openai.com
  - type: domain
    value: chatgpt.com
  - type: domain
    value: copilot.microsoft.com
  - type: domain
    value: bard.google.com
  - type: domain
    value: gemini.google.com
  - type: domain
    value: claude.ai
  - type: domain
    value: perplexity.ai
  - type: domain
    value: poe.com
  - type: domain
    value: chat.forefront.ai
  - type: domain
    value: chat.deepseek.com
  - type: domain
    value: openclaw.ai
ioc_counts:
  domain: 35
rules:
  - title: Detect DNS Queries to Common LLM Endpoints by Scripting Utilities
    description: Detects DNS queries to known LLM domains from scripting utilities like PowerShell or wscript, indicating potential command and control activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1102.002
    data_sources:
      - dns_query
      - windows
  - title: Detect LLM Endpoint DNS Queries from Unsigned Executables
    description: Detects DNS queries to known LLM domains from unsigned executables, potentially indicating malware activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1102.002
    data_sources:
      - dns_query
      - windows
  - title: Detect LLM Endpoint DNS Queries from Uncommon Process Locations
    description: Detects DNS queries to known LLM domains from executables running from unusual locations like temp directories, indicating potential malware activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1102.002
    data_sources:
      - dns_query
      - windows
rules_count: 3
---

This detection identifies suspicious network connections to known Large Language Model (LLM) APIs and chat portals. It focuses on detecting anomalous processes, such as scripting utilities or unsigned executables, making DNS requests to these LLM services. The assumption is that malware may be attempting to leverage LLMs to perform dynamic actions, such as receiving instructions or exfiltrating data via the LLM service. This behavior began appearing in threat intelligence reports in late 2025 and continues to evolve. The detection aims to catch malware abusing legitimate LLM services for command and control, blending in with normal network traffic. This detection helps identify command and control using LLMs, which can dynamically adapt malware behavior, making traditional signature-based detections less effective.

## Attack Chain

1. An attacker compromises a system through an initial access vector, such as exploiting a vulnerability or using social engineering.
2. The attacker deploys a malicious script (e.g., PowerShell, JavaScript) or an unsigned executable onto the compromised host.
3. The malicious script or executable performs a DNS query to resolve a known LLM API endpoint (e.g., api.openai.com, api.anthropic.com).
4. The script or executable establishes a network connection to the resolved LLM API endpoint using HTTP/HTTPS.
5. The malicious actor sends a command to the compromised system through the LLM API, disguised as a normal user request.
6. The compromised system receives the command from the LLM API and executes it. This might involve actions such as data exfiltration, lateral movement, or deploying further payloads.
7. The system sends the results of the executed command back to the attacker through the LLM API.
8. This bidirectional communication repeats, allowing the attacker to maintain persistent command and control over the compromised system via the LLM service.

## Impact

Successful exploitation allows attackers to execute arbitrary commands on compromised systems, potentially leading to data theft, system disruption, or further propagation within the network. Given the increasing reliance on LLMs, this attack vector could affect a wide range of organizations and industries. The compromised system effectively becomes part of a botnet controlled via LLM infrastructure, making attribution and takedown more difficult. The use of LLMs can also make the attack more difficult to detect, as the network traffic blends in with legitimate LLM usage.

## Recommendation

*   Deploy the Sigma rule "Detect DNS Queries to Common LLM Endpoints by Scripting Utilities" to your SIEM and tune for your environment, focusing on process names and command-line arguments.
*   Monitor DNS query logs for connections to the LLM domains listed in the IOC table originating from unusual or unsigned processes.
*   Investigate any alerts generated by the Sigma rules, paying close attention to the process execution chain and any associated network activity.
*   Implement network segmentation to limit the impact of compromised systems and restrict outbound connections to trusted LLM services.
*   Enable process-creation logging, including command-line arguments, to activate the rules above.
*   Block the C2 domains listed in the IOC table at the DNS resolver.
