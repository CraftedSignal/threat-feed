---
title: Detection of Local LLM Model File Creation on Endpoints
slug: 2026-07-llm-model-file-creation
description: This brief describes how the creation of Large Language Model (LLM) files, including formats like .gguf, .safetensors, .ggml, and Modelfiles, by local AI inference frameworks such as Ollama, llama.cpp, GPT4All, and LM Studio can be detected on Windows endpoints, indicating potential shadow AI deployments, unauthorized model downloads, or rogue LLM infrastructure which poses data exfiltration risks and policy violations.
date: "2026-07-27T18:17:13Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - shadow-it
  - llm
  - data-exfiltration
  - policy-violation
  - endpoint
vendors:
  - Ollama
products:
  - Ollama
  - llama.cpp
  - GPT4All
  - LM Studio
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: This detection identifies potential shadow AI deployments, unauthorized model downloads, and rogue LLM infrastructure by detecting file creation patterns associated with local inference frameworks such as Ollama, llama.cpp, GPT4All, LM Studio, and similar tools that enable running LLMs locally without cloud dependencies.
    confidence_band: med
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: This detection identifies potential shadow AI deployments, unauthorized model downloads, and rogue LLM infrastructure by detecting file creation patterns associated with local inference frameworks such as Ollama, llama.cpp, GPT4All, LM Studio, and similar tools that enable running LLMs locally without cloud dependencies.
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: These file types are characteristic of local inference frameworks such as Ollama, llama.cpp, GPT4All, LM Studio, and similar tools that enable running LLMs locally without cloud dependencies.
    confidence_band: med
references:
  - https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
  - https://www.ibm.com/think/topics/shadow-ai
  - https://www.splunk.com/en_us/blog/artificial-intelligence/splunk-technology-add-on-for-ollama.html
  - https://blogs.cisco.com/security/detecting-exposed-llm-servers-shodan-case-study-on-ollama
rules:
  - title: Detect Local LLM Model File Creation
    description: Detects the creation of Large Language Model (LLM) files by monitoring file creation events for specific model file formats and extensions used by local AI frameworks. This helps identify potential shadow AI deployments and unauthorized model downloads.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
      - exfiltration
      - persistence
      - privilege_escalation
    techniques:
      - T1543
    data_sources:
      - file_event
      - windows
rules_count: 1
---

This threat brief focuses on the detection of Large Language Model (LLM) file creation on Windows endpoints, a key indicator of potential "shadow AI" deployments or unauthorized local LLM infrastructure. Organizations are facing increasing risks from employees downloading and running open-source or local LLMs on corporate devices, often bypassing established security controls and data governance policies. These local inference frameworks, such as Ollama, llama.cpp, GPT4All, and LM Studio, utilize specific file formats like quantized models (.gguf, .ggml), safetensors files, and proprietary Modelfiles. The creation of these files suggests that LLMs are being run locally, potentially processing sensitive company data outside of approved, monitored environments. This can lead to significant data exfiltration risks, intellectual property leakage, and security blind spots, as these decentralized AI deployments often operate without the oversight of enterprise monitoring systems, making it difficult to track data usage and ensure compliance. This detection method provides visibility into such activities, enabling defenders to identify and mitigate these risks proactively.

## Attack Chain

This brief describes a detection for the presence of unauthorized Large Language Model (LLM) files, rather than a specific attack chain or exploitation scenario. The detection focuses on identifying the creation of specific file types associated with local LLM inference engines. While the creation of these files is not an "attack" in itself, it indicates the establishment of a local environment that can be leveraged for various malicious or policy-violating activities. Therefore, a traditional multi-step attack chain, from initial access to impact, is not directly applicable or described in the source material for this specific detection.

## Impact

The primary impact of undetected local LLM model file creation is the potential for significant data exfiltration and intellectual property loss. Employees using unapproved LLMs on corporate devices might inadvertently or intentionally feed sensitive company data into these models, leading to data breaches or compliance violations. The proliferation of shadow AI infrastructure creates severe security blind spots, making it challenging for security teams to monitor data flows, detect malicious activity, and ensure adherence to organizational policies. Furthermore, these rogue LLM deployments can consume significant system resources, impacting legitimate business operations, and introduce new attack vectors if the downloaded models or frameworks contain vulnerabilities or malicious code. Without proper governance, organizations face increased legal, reputational, and financial risks due to unmanaged AI usage.

## Recommendation

* Deploy the Sigma rule `Detect_Local_LLM_Model_File_Creation` to your SIEM solution to identify instances of LLM model file creation.
* Ensure Sysmon Event ID 11 (File Creation) logging is enabled across all Windows endpoints to provide the necessary telemetry for the rule.
* Regularly review alerts generated by `Detect_Local_LLM_Model_File_Creation` and investigate the context of LLM file creation to determine if it is authorized or represents a policy violation.
* Educate employees about the risks associated with unauthorized local LLM usage and the proper channels for AI tool adoption to mitigate data exfiltration risks and policy violations.
