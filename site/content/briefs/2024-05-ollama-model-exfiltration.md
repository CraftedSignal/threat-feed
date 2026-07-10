---
title: Ollama Model Exfiltration Attempt Detection
slug: 2024-05-ollama-model-exfiltration
description: This brief describes detection of potential data exfiltration attempts targeting Ollama model metadata and configuration endpoints by adversaries repeatedly querying specific API endpoints to extract sensitive model information.
date: "2024-05-02T14:22:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ollama
  - model-exfiltration
  - data-leakage
vendors:
  - Ollama
products:
  - Ollama
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
references:
  - https://github.com/rosplk/ta-ollama
rules:
  - title: Ollama Model Metadata Exfiltration via API
    description: Detects potential Ollama model metadata exfiltration by monitoring requests to sensitive API endpoints.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1048
    data_sources:
      - webserver
      - linux
  - title: Ollama High Response Time on Model API Endpoint
    description: Detects unusually high response times on Ollama model API endpoints, potentially indicating a large data exfiltration attempt.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1048
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This detection focuses on identifying potential data exfiltration attempts against Ollama, a framework for running large language models locally. The technique involves adversaries repeatedly querying specific API endpoints such as `/api/show`, `/api/tags`, and `/api/v1/models`. These queries are designed to extract sensitive model information including architecture details, fine-tuning parameters, system paths, Modelfile configurations, and any proprietary customizations. The detection logic flags instances where multiple inspection attempts occur within a short 15-minute window, suggesting automated exfiltration activity. Successful exfiltration could lead to competitive intelligence gathering, model replication, or preparation for further attacks against the AI infrastructure.

## Attack Chain

1.  The attacker gains initial access to a system capable of making requests to the Ollama server.
2.  The attacker begins sending HTTP GET requests to the `/api/tags` endpoint to enumerate available models.
3.  For each model identified, the attacker sends HTTP GET requests to the `/api/show` endpoint to retrieve detailed model metadata.
4.  The attacker may also query `/api/v1/models` to gather additional model-related information.
5.  The attacker parses the JSON responses to extract sensitive information such as model architecture, system prompts, and custom configurations.
6.  The extracted data is aggregated and prepared for exfiltration.
7.  The attacker initiates exfiltration, potentially using techniques like DNS tunneling, HTTP POST requests to external servers, or cloud storage uploads.
8.  The attacker uses the exfiltrated information to replicate the model, gain competitive insights, or identify vulnerabilities in the AI infrastructure.

## Impact

Successful exfiltration of Ollama model metadata can have significant consequences. Competitors could replicate proprietary models, undermining the victim's competitive advantage. Attackers could use the exfiltrated data to identify vulnerabilities in the AI infrastructure, paving the way for more sophisticated attacks. The unauthorized disclosure of sensitive model configurations, system prompts, and internal model specifications can lead to substantial financial and reputational damage.

## Recommendation

*   Deploy the provided Sigma rule `Ollama Model Metadata Exfiltration via API` to your SIEM to detect suspicious API access patterns (logsource: `webserver`, product: `linux`).
*   Monitor Ollama server logs for unusually high request rates to `/api/show`, `/api/tags`, and `/api/v1/models` (logsource: `webserver`, product: `linux`).
*   Implement rate limiting on the Ollama API endpoints to prevent automated exfiltration attempts (firewall/WAF configuration).
*   Review and harden access controls to the Ollama server to prevent unauthorized access (Ollama configuration).
