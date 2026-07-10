---
title: Ollama Resource Exhaustion via Memory Abuse
slug: 2024-01-03-ollama-resource-exhaustion
description: This brief covers a technique to detect resource exhaustion attacks against Ollama servers by monitoring abnormal memory allocation and runner operations, potentially leading to denial of service or performance degradation.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ollama
  - resource-exhaustion
  - denial-of-service
vendors:
  - Ollama
products:
  - Ollama
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/splunk/security_content/blob/main/detections/application/ollama_possible_memory_exhaustion_resource_abuse.yml
  - https://github.com/rosplk/ta-ollama
rules:
  - title: Ollama High Memory Allocation
    description: Detects suspicious Ollama processes allocating excessive memory, potentially indicating resource exhaustion attempts.
    platform: sigma
    severity: high
    tactics:
      - resource_hijacking
    techniques:
      - T1499
    data_sources:
      - process_creation
      - linux
  - title: Ollama Excessive Runner Processes
    description: Detects a large number of Ollama runner processes being created, potentially indicative of a resource exhaustion attack.
    platform: sigma
    severity: medium
    tactics:
      - resource_hijacking
    techniques:
      - T1499
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This threat brief addresses potential resource exhaustion attacks targeting Ollama servers. Adversaries might attempt to degrade system performance or cause denial of service by overloading the server with excessive memory allocation requests and runner operations. This can be achieved by loading multiple large language models, repeatedly triggering model initialization, or exploiting memory allocation mechanisms. The attack aims to overwhelm CPU/GPU resources and exhaust available memory. Defenders should monitor Ollama server logs for unusual patterns in memory allocation, runner counts, and the frequency of operations. The Splunk search provided by the source content is designed to detect such anomalies.

## Attack Chain

1.  Attacker gains access to a system capable of interacting with the Ollama server. This could be a compromised host within the network or an external system with network access.
2.  The attacker sends a series of requests to the Ollama server to load large language models. The attacker may automate these requests to rapidly increase the number of models being loaded.
3.  The Ollama server attempts to allocate memory for each requested model. This process consumes system memory, including RAM and potentially swap space.
4.  The attacker sends requests to repeatedly initialize or re-initialize models, forcing the Ollama server to perform redundant memory allocation operations.
5.  The Ollama server's runner count increases as it attempts to manage the numerous model instances. This puts additional strain on CPU resources.
6.  Memory usage on the Ollama server spikes, potentially exceeding available resources.
7.  The server's performance degrades, leading to slow response times or complete unresponsiveness. Legitimate users may experience denial of service.
8.  The attacker maintains the attack until the Ollama server becomes unusable or system administrators intervene.

## Impact

A successful resource exhaustion attack on an Ollama server can lead to significant disruption. Victims may experience denial of service, preventing legitimate users from accessing the server's capabilities. Degraded performance can impact the usability of applications relying on the Ollama server. The attack can exhaust system resources, potentially affecting other services running on the same host. The severity depends on the size and configuration of the Ollama server and the scale of the attack.

## Recommendation

*   Deploy the Sigma rule `Ollama High Memory Allocation` to detect abnormal memory usage by Ollama processes (logsource: `process_creation`).
*   Deploy the Sigma rule `Ollama Excessive Runner Processes` to detect a large number of Ollama runner processes being created (logsource: `process_creation`).
*   Monitor the `ollama_server` logs for spikes in memory allocation and runner counts as described in the Splunk search (data_source: `Ollama Server`).
*   Tune the thresholds in the Splunk search provided to suit your environment, focusing on `operations`, `total_runners`, `max_memory`, and `total_memory` (search).
*   Implement rate limiting and request validation on the Ollama API to prevent excessive model loading requests (references: `https://github.com/rosplk/ta-ollama`).
