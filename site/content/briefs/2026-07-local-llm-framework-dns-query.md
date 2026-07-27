---
title: Detection of Local LLM Framework DNS Queries
slug: 2026-07-local-llm-framework-dns-query
description: This brief details the detection of DNS queries originating from local Large Language Model (LLM) frameworks like Ollama, LM Studio, and GPT4All on Windows endpoints, leveraging Sysmon Event ID 22 to identify potential unauthorized AI tool usage or data exfiltration risks associated with model downloads, updates, and telemetry from repositories such as huggingface.co and ollama.ai.
date: "2026-07-27T18:18:49Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - local-llm
  - shadow-ai
  - dns-monitoring
  - data-exfiltration
  - policy-violation
  - windows
  - endpoint-security
vendors:
  - Anthropic
  - OpenAI
  - Ollama
  - LM Studio
  - Hugging Face
  - Nomic AI
  - Replicate
  - Alibaba Cloud
  - OpenRouter
products:
  - Claude
  - ChatGPT
  - Codex
  - Ollama
  - LM Studio
  - GPT4All
  - huggingface.co
  - jan.ai
  - nomic.ai
  - replicate.com
  - civitai.com
  - KoboldAI
  - Oobabooga Text Generation Web UI
  - modelscope.cn
  - Dashscope
  - Tongyi
  - openrouter.ai
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: These queries can reveal unauthorized AI tool usage or data exfiltration risks on corporate networks.
    confidence_band: high
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1588
    technique_name: ""
    evidence: Local LLM frameworks like Ollama, LM Studio, and GPT4All make DNS calls to repositories such as huggingface.co and ollama.ai for model downloads, updates, and telemetry.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1590
    technique_name: Gather Victim Network Information
    evidence: Detects DNS queries related to local LLM models on endpoints by monitoring Sysmon DNS query events... These queries can reveal unauthorized AI tool usage or data exfiltration risks on corporate networks.
    confidence_band: med
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/local_llm_framework_dns_query.yml
  - https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
  - https://www.splunk.com/en_us/blog/artificial-intelligence/splunk-technology-add-on-for-ollama.html
  - https://blogs.cisco.com/security/detecting-exposed-llm-servers-shodan-case-study-on-ollama
iocs:
  - type: domain
    value: anthropic.com
  - type: domain
    value: api.openrouter.com
  - type: domain
    value: civitai.com
  - type: domain
    value: dashscope.aliyuncs.com
  - type: domain
    value: gpt4all.io
  - type: domain
    value: huggingface.co
  - type: domain
    value: jan.ai
  - type: domain
    value: koboldai.org
  - type: domain
    value: lmstudio.ai
  - type: domain
    value: modelscope.cn
  - type: domain
    value: nomic.ai
  - type: domain
    value: ollama.ai
  - type: domain
    value: ollama.com
  - type: domain
    value: oobabooga.org
  - type: domain
    value: openai.com
  - type: domain
    value: openrouter.ai
  - type: domain
    value: replicate.com
  - type: domain
    value: tongyi.aliyun.com
ioc_counts:
  domain: 18
rules:
  - title: Detect Local LLM Framework DNS Queries
    description: Detects DNS queries to known LLM model repositories and services, indicative of potential unauthorized local LLM framework usage or data exfiltration risks on Windows endpoints.
    platform: sigma
    severity: medium
    tactics:
      - impact
      - reconnaissance
      - resource_development
    techniques:
      - T1041
      - T1588.002
      - T1590
    data_sources:
      - dns_query
      - windows
rules_count: 1
---

This threat brief outlines the detection of DNS queries made by local Large Language Model (LLM) frameworks operating on Windows endpoints. Organizations are increasingly facing challenges with "shadow AI" as employees independently deploy local LLM tools such as Ollama, LM Studio, and GPT4All. These frameworks often make DNS calls to various external repositories and services, including huggingface.co, ollama.ai, and openai.com, for model downloads, updates, and telemetry. Such network activity, captured via Sysmon DNS query events (Event ID 22), can indicate unauthorized software usage, potential policy violations, and, critically, data exfiltration risks if sensitive corporate information is processed by these unmanaged models or sent out through their telemetry. Detecting these queries is vital for maintaining network security, protecting intellectual property, and ensuring compliance within corporate environments.

## Impact

The unauthorized use of local LLM frameworks within an enterprise environment poses several significant risks. It can lead to the processing of sensitive corporate data by unvetted and unmanaged applications, creating avenues for inadvertent data leakage or malicious exfiltration through model telemetry or update mechanisms. Such activities also bypass established security controls and introduce unmonitored software, contributing to "shadow IT" environments that are difficult to secure and audit. This can result in intellectual property theft, violations of regulatory compliance, and a general erosion of data governance policies, potentially causing financial damages and reputational harm to the organization.

## Recommendation

* Enable Sysmon process creation and DNS query logging (Event ID 22) across all Windows endpoints to ensure the necessary telemetry for this detection is collected.
* Deploy the "Detect Local LLM Framework DNS Queries" Sigma rule to your SIEM and tune it for your specific environment, creating exceptions for authorized LLM usage by developers or sanctioned AI/ML workstations.
* Block the IOCs listed in this brief at your network perimeter (e.g., DNS resolver, proxy, firewall) to prevent unauthorized access to known LLM model repositories and services.
* Review network logs and endpoint telemetry for any activity matching the DNS query patterns identified in the "Detect Local LLM Framework DNS Queries" rule and investigate originating processes.
