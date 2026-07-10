---
title: Ollama Server Possible RCE via Malicious Model Loading
slug: 2024-01-03-ollama-rce
description: The detection identifies potential remote code execution attempts on Ollama servers through malicious model loading by monitoring error messages and failure patterns during model loading operations, which could indicate malicious model injection, path traversal attempts, or exploitation of model loading mechanisms, leading to arbitrary code execution on the server.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - ollama
  - rce
  - model-injection
vendors:
  - Ollama
products:
  - Ollama Server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/rosplk/ta-ollama
rules:
  - title: Ollama Possible RCE via Model Loading
    description: Detects Ollama server errors during model loading operations indicative of malicious model injection or path traversal attempts leading to potential remote code execution.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - application
      - ollama
  - title: Ollama Service Crash Detection
    description: Detects instances where the Ollama service crashes unexpectedly, potentially due to a malicious model or exploitation attempt.
    platform: sigma
    severity: high
    tactics:
      - impact
    data_sources:
      - application
      - ollama
rules_count: 2
---

This brief addresses a critical vulnerability in Ollama servers that could lead to remote code execution (RCE). The threat involves attackers attempting to load malicious models onto the server to execute arbitrary code. This is achieved by exploiting vulnerabilities in the model loading process or by injecting specially crafted models designed to trigger server errors and allow code execution. The detection focuses on identifying unusual error patterns during model loading, such as crashes, failures related to "llama runner," and model-specific errors. This activity may originate from an external threat actor or a malicious insider attempting to compromise the Ollama server. Successful exploitation allows the attacker to gain full control of the server.

## Attack Chain

1.  The attacker identifies an Ollama server with accessible model loading functionality.
2.  The attacker crafts a malicious model or exploits an existing model.
3.  The attacker initiates a model loading request to the Ollama server.
4.  The Ollama server attempts to load the model.
5.  The malicious model triggers an error within the llama runner component or the model processing logic.
6.  The error leads to a service crash or code execution due to vulnerabilities in the model loader.
7.  The attacker gains remote code execution on the Ollama server.

## Impact

A successful attack can lead to complete compromise of the Ollama server. The attacker gains the ability to execute arbitrary code, potentially leading to data exfiltration, denial of service, or further lateral movement within the network. The risk is heightened due to the potential for sensitive data stored or processed by the Ollama server to be exposed or manipulated. The number of victims and specific sectors targeted are unknown, but the impact is potentially widespread given the increasing adoption of Ollama servers.

## Recommendation

*   Deploy the `Ollama Possible RCE via Model Loading` Sigma rule to your SIEM to detect suspicious model loading errors on Ollama servers.
*   Review and harden the Ollama server configuration to restrict model loading permissions and validate model integrity.
*   Implement network segmentation to limit the impact of a compromised Ollama server.
*   Investigate any detected instances of model loading errors and potential RCE attempts based on the Sigma rule output.
