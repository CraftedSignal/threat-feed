---
title: LiteLLM Package Compromised with Credential-Stealing Code via Trivy
slug: 2026-03-litellm-credential-theft
description: The LiteLLM package was compromised and infected with credential-stealing code through a supply chain attack leveraging the Trivy vulnerability scanner.
date: "2026-03-25T12:00:00Z"
severities:
  - critical
tags:
  - supply-chain
  - credential-theft
  - llm
  - trivy
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://www.reddit.com/r/cybersecurity/comments/1s2tau0/litellm_infected_with_credentialstealing_code_via/
  - https://www.theregister.com/2026/03/24/trivy_compromise_litellm/
rules:
  - title: Detect Suspicious LiteLLM Outbound Connection
    description: Detects potentially malicious outbound network connections from the LiteLLM package. This may indicate credential exfiltration.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect LiteLLM Credential Access via Env
    description: Detects access to environment variables that may contain credentials within LiteLLM
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On March 24, 2026, reports surfaced indicating that the LiteLLM package, a library designed to provide a unified interface for interacting with various large language models, was compromised and injected with malicious code. This compromise occurred through a vulnerability in Trivy, a widely-used open-source vulnerability scanner. The malicious code was designed to steal credentials, potentially including API keys and other sensitive information used to access and manage language models. The…
