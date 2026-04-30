---
title: LiteLLM Package Compromised with Credential-Stealing Code via Trivy
slug: 2026-03-litellm-credential-theft
description: The LiteLLM package was compromised and infected with credential-stealing code through a supply chain attack leveraging the Trivy vulnerability scanner.
date: "2026-03-25T12:00:00Z"
type: advisory
types:
  - advisory
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

On March 24, 2026, reports surfaced indicating that the LiteLLM package, a library designed to provide a unified interface for interacting with various large language models, was compromised and injected with malicious code. This compromise occurred through a vulnerability in Trivy, a widely-used open-source vulnerability scanner. The malicious code was designed to steal credentials, potentially including API keys and other sensitive information used to access and manage language models. The scope of the compromise is currently unknown, but given the popularity of both LiteLLM and Trivy, the potential impact could be significant across various sectors using LLMs. This incident highlights the risks associated with supply chain vulnerabilities and the importance of thorough security audits of third-party dependencies.

## Attack Chain

1.  A vulnerability is exploited within Trivy, potentially during its build or update process.
2.  The attacker leverages this vulnerability to inject malicious code into the LiteLLM package during its build or release process.
3.  Users download and install the compromised LiteLLM package from the official repository (e.g., PyPI).
4.  Upon execution of the infected LiteLLM package, the malicious code is triggered.
5.  The malicious code collects credentials, such as API keys, environment variables, or configuration files, from the user's system or environment.
6.  The stolen credentials are exfiltrated to a remote server controlled by the attacker using network protocols like HTTP/S.
7.  The attacker uses the stolen credentials to access and control the victim's accounts, resources, and data related to language model services.
8.  The attacker may further exploit the compromised systems for lateral movement, data exfiltration, or other malicious activities.

## Impact

The successful compromise of the LiteLLM package can lead to significant damage, including unauthorized access to language model APIs, data breaches, and financial losses. The number of affected users and organizations is currently unknown. Sectors relying heavily on LLMs, such as AI development, research, and various industries integrating AI-powered applications, are particularly vulnerable. If successful, the attack can result in the exposure of sensitive data, disruption of services, and reputational damage.

## Recommendation

*   Implement integrity checks on all downloaded packages to verify their authenticity and prevent the installation of compromised versions (reference: overview).
*   Monitor network traffic for suspicious outbound connections originating from processes associated with the LiteLLM package, looking for connections to unknown or malicious IPs (reference: Attack Chain, step 6).
*   Deploy the Sigma rules provided below to detect potential credential theft and exfiltration attempts (reference: rules).
*   Implement strict access controls and least privilege principles to limit the impact of compromised credentials (reference: Impact).
*   Conduct regular security audits of all third-party dependencies and use software composition analysis tools to identify and remediate vulnerabilities (reference: Overview).
