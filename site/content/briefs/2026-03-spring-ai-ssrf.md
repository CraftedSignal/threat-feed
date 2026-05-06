---
title: Spring AI BedrockProxyChatModel SSRF Vulnerability (CVE-2026-22742)
slug: 2026-03-spring-ai-ssrf
description: Spring AI's spring-ai-bedrock-converse library is vulnerable to Server-Side Request Forgery (SSRF) due to insufficient validation of user-supplied media URLs in multimodal messages, allowing attackers to trigger HTTP requests to internal or external destinations.
date: "2026-03-27T06:16:37Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - ssrf
  - spring-ai
  - bedrockproxychatmodel
  - cve-2026-22742
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22742
  - https://spring.io/security/cve-2026-22742
rules:
  - title: Detect Suspicious Outbound Connection from Spring AI
    description: Detects outbound network connections from the Spring AI application server to unusual or internal IP addresses, indicating potential SSRF exploitation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect Multimodal Messages with Suspicious URL Patterns
    description: Detects requests containing multimodal messages with URLs that resemble common SSRF payloads.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A Server-Side Request Forgery (SSRF) vulnerability has been identified in the spring-ai-bedrock-converse library within Spring AI. The vulnerability resides in the BedrockProxyChatModel component and arises during the processing of multimodal messages. Specifically, when handling user-supplied media URLs, the application fails to adequately validate these URLs. This lack of validation allows a malicious actor to inject arbitrary URLs, potentially causing the server to make unintended HTTP…
