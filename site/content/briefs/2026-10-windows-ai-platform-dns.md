---
title: Anomalous DNS Queries to AI Service Providers
slug: 2026-10-windows-ai-platform-dns
description: This detection targets anomalous DNS activity where endpoints initiate connections to external AI service providers like Hugging Face or OpenAI, which may indicate data exfiltration or the use of AI APIs for command-and-control communication.
date: "2026-10-05T12:17:02Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - data-exfiltration
  - command-and-control
  - windows
vendors:
  - Microsoft
  - OpenAI
  - Hugging Face
products:
  - Windows AI Platform
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Monitoring these DNS requests is important because it can reveal when systems are accessing external AI platforms, which may indicate the use of third-party AI resources or the transfer of sensitive data outside the organization’s environment.
    confidence_band: high
references:
  - https://cert.gov.ua/article/6284730
  - https://www.microsoft.com/en-us/security/blog/2025/11/03/sesameop-novel-backdoor-uses-openai-assistants-api-for-command-and-control/
iocs:
  - type: domain
    value: router.huggingface.co
  - type: domain
    value: api.openai.com
ioc_counts:
  domain: 2
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable Sysmon DNS logging and monitor traffic to the specified domains.
      owner: SOC
      due: 24h
      evidence: Source requirement for EventCode 22.
  hunt_leads:
    - lead: Search for DNS queries to ai platform domains from non-browser processes.
      technique_id: T1071.004
      data_needed:
        - Sysmon Event ID 22
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Analytic provided in source.
---

Monitoring DNS requests originating from endpoints to known AI service providers is critical for identifying potential unauthorized data exfiltration or the misuse of generative AI infrastructure for command-and-control (C2) purposes. Recent intelligence, including the SesameOp campaign, has highlighted how attackers leverage services like the OpenAI Assistants API to establish covert communication channels. Unauthorized access to platforms such as Hugging Face and OpenAI may also indicate the inadvertent or intentional transfer of proprietary or sensitive internal data to external models. This analytic focuses on identifying non-standard processes attempting to resolve domain names associated with popular AI platforms, allowing security teams to enforce data governance and maintain visibility into suspicious outbound traffic patterns.

## Impact

Successful exploitation of these patterns can lead to the exfiltration of intellectual property, the bypass of internal data loss prevention controls, and the establishment of persistent, difficult-to-detect C2 infrastructure leveraging legitimate cloud-based AI services. Organizations failing to monitor these outbound flows risk losing control over sensitive internal information processed by external model providers.

## Recommendation

- Enable Sysmon Event ID 22 (DNS Query) logging across all endpoints to capture the required telemetry.
- Implement the provided detection logic to flag unexpected processes communicating with `api.openai.com` or `router.huggingface.co`.
- Maintain an allowlist of authorized applications and services permitted to communicate with AI model APIs to reduce false positives from research or development teams.
- Investigate any alerts identifying non-standard processes, especially those lacking digital signatures, initiating connections to these domains.
