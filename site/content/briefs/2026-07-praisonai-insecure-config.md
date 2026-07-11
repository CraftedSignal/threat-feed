---
title: Insecure Default Configuration in PraisonAI Allows Unauthenticated Access
slug: 2026-07-praisonai-insecure-config
description: An insecure default configuration in PraisonAI before version 1.7.3 allows unauthenticated attackers to exploit CVE-2026-61426 by reading sensitive agent instructions and system prompts via the `/api/agents` endpoint and invoking agents without authentication through the `/api/chat` endpoint, leading to unauthorized information disclosure and potential control over AI functionalities.
date: "2026-07-11T14:21:33Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - web-application
  - insecure-configuration
  - PraisonAI
  - cve
vendors:
  - MervinPraison
products:
  - PraisonAI
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can call GET /api/agents to read agent instructions and system prompts, or POST /api/chat to invoke agents without authentication.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: Unauthenticated attackers can call GET /api/agents to read agent instructions and system prompts.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Unauthenticated attackers can... POST /api/chat to invoke agents without authentication.
    confidence_band: med
cves:
  - id: CVE-2026-61426
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61426
  - https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-6wjp-v33h-5cvq
  - https://www.vulncheck.com/advisories/praisonai-before-unauthenticated-agent-access-via-insecure-defaults
rules:
  - title: Detects CVE-2026-61426 Exploitation - GET /api/agents
    description: Detects exploitation attempts for CVE-2026-61426 where an unauthenticated attacker performs an HTTP GET request to the /api/agents endpoint to read sensitive agent instructions and system prompts.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1190
      - T1592.004
    data_sources:
      - webserver
  - title: Detects CVE-2026-61426 Exploitation - POST /api/chat
    description: Detects exploitation attempts for CVE-2026-61426 where an unauthenticated attacker performs an HTTP POST request to the /api/chat endpoint to invoke agents without authentication.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1078.004
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

CVE-2026-61426 details a critical security vulnerability in PraisonAI software versions prior to 1.7.3. The vulnerability stems from an insecure default configuration where the application binds to all network interfaces without requiring API keys for sensitive operations and utilizes a wildcard CORS policy. This flaw permits unauthenticated attackers to make direct HTTP requests to internal API endpoints. Specifically, attackers can issue a GET request to `/api/agents` to retrieve confidential agent instructions and system prompts, effectively exposing proprietary logic and sensitive data. Furthermore, the absence of authentication allows attackers to send POST requests to `/api/chat`, enabling them to invoke agents and interact with the AI functionalities without authorization. This vulnerability has a CVSS v3.1 base score of 8.6 (High), highlighting its significant risk. Organizations utilizing PraisonAI instances, particularly those exposed to the internet, are at risk of unauthorized access, intellectual property theft, and potential misuse of their AI agents.

## Attack Chain

1. **Discovery of Public-Facing PraisonAI Instance**: An unauthenticated attacker scans for internet-exposed PraisonAI instances, identifying applications running vulnerable versions.
2. **Unauthenticated Information Gathering (GET /api/agents)**: The attacker sends an unauthenticated HTTP GET request to the `/api/agents` endpoint of the vulnerable PraisonAI application.
3. **Sensitive Information Exposure**: Due to the insecure default configuration (no API key requirement and wildcard CORS), the PraisonAI instance responds with agent instructions and system prompts, disclosing sensitive internal configuration and AI logic.
4. **Unauthenticated Agent Invocation (POST /api/chat)**: Leveraging the absence of authentication, the attacker then crafts and sends an unauthenticated HTTP POST request to the `/api/chat` endpoint.
5. **Unauthorized Agent Operation**: The PraisonAI application processes the POST request without validating user credentials, allowing the attacker to invoke and interact with AI agents, potentially leading to unauthorized operations or manipulation of AI services.

## Impact

Successful exploitation of CVE-2026-61426 leads to severe consequences, primarily unauthorized access to sensitive information and control over AI functionalities. Attackers can exfiltrate proprietary agent instructions and system prompts, which could contain business logic, trade secrets, or data handling methodologies. This exposure can lead to intellectual property theft or provide attackers with insights to further compromise the system. Additionally, the ability to invoke agents without authentication means an attacker can misuse AI resources, potentially consuming computational resources, generating malicious content, or interacting with other systems the AI agents are authorized to access. While no specific victim counts are provided, any organization running an unpatched PraisonAI instance with public exposure is at high risk.

## Recommendation

* **Patch CVE-2026-61426**: Immediately update all PraisonAI instances to version 1.7.3 or higher to address the insecure default configuration.
* **Deploy Detection Rules**: Deploy the provided Sigma rules (`Detects CVE-2026-61426 Exploitation - GET /api/agents` and `Detects CVE-2026-61426 Exploitation - POST /api/chat`) to your SIEM to detect exploitation attempts.
* **Review Network Exposure**: Configure network firewalls and access controls to restrict direct internet access to PraisonAI instances, particularly on sensitive API endpoints.
* **Enable Web Server Logging**: Ensure comprehensive web server logging is enabled to capture HTTP method, URI stem, and request details for forensic analysis and detection rule activation.
