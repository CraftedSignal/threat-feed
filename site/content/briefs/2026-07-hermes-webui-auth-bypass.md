---
title: 'CVE-2026-58122: Hermes WebUI Authentication Bypass via Spoofed X-Forwarded-For Header'
slug: 2026-07-hermes-webui-auth-bypass
description: CVE-2026-58122 describes an authentication bypass vulnerability in Hermes WebUI before version 0.51.307, allowing unauthenticated remote attackers to bypass local-origin IP restrictions on onboarding endpoints by spoofing the X-Forwarded-For header with a loopback address, leading to server-side request forgery (SSRF), API key overwrites, and persistent access token acquisition.
date: "2026-07-09T22:18:52Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - ssrf
  - web-vulnerability
  - credential-theft
  - persistence
  - cloud
  - network
vendors:
  - Hermes
products:
  - Hermes WebUI < 0.51.307
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Hermes WebUI before 0.51.307 contains an authentication bypass vulnerability that allows unauthenticated remote attackers to circumvent local-origin IP restrictions on onboarding endpoints
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: authentication bypass vulnerability that allows unauthenticated remote attackers to circumvent local-origin IP restrictions on onboarding endpoints by supplying a spoofed X-Forwarded-For header with a loopback address.
    confidence_band: med
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: overwrite LLM provider configuration and API keys with attacker-controlled values, or initiate OAuth device-code flows to obtain persistent access tokens stored in auth.json.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: obtain persistent access tokens stored in auth.json.
    confidence_band: high
cves:
  - id: CVE-2026-58122
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58122
rules:
  - title: Detects CVE-2026-58122 Exploitation - Hermes WebUI Auth Bypass via X-Forwarded-For
    description: Detects CVE-2026-58122 exploitation where unauthenticated remote attackers bypass local-origin IP restrictions on Hermes WebUI onboarding endpoints by supplying a spoofed X-Forwarded-For header with a loopback address. This indicates an attempt at SSRF.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1190
      - T1552.001
    data_sources:
      - webserver
rules_count: 1
---

Unauthenticated remote attackers can exploit CVE-2026-58122, an authentication bypass vulnerability affecting Hermes WebUI versions prior to 0.51.307. This vulnerability allows attackers to circumvent local-origin IP restrictions on specific "onboarding endpoints" by manipulating the `X-Forwarded-For` HTTP header. By supplying a spoofed loopback address (e.g., 127.0.0.1) in this header, the attacker can deceive the application into believing the request originates from an internal, trusted source. This bypass facilitates server-side request forgery (SSRF), enabling attackers to interact with internal services, including sensitive cloud metadata endpoints. Successful exploitation can lead to critical consequences such as overwriting Large Language Model (LLM) provider configurations and API keys with attacker-controlled values, or initiating OAuth device-code flows to obtain persistent access tokens stored within the `auth.json` file.

## Attack Chain

1. An unauthenticated remote attacker sends an HTTP request to a vulnerable Hermes WebUI server before version 0.51.307.
2. The attacker targets specific "onboarding endpoints" within the Hermes WebUI application.
3. The attacker crafts the HTTP request to include a spoofed `X-Forwarded-For` header, setting its value to a loopback address (e.g., `127.0.0.1`).
4. The Hermes WebUI processes the spoofed header, bypassing its local-origin IP restrictions, and interprets the request as originating from a trusted internal source.
5. The attacker then leverages this bypass to perform server-side request forgery (SSRF) against internal services accessible from the WebUI, including cloud metadata endpoints.
6. Through the SSRF, the attacker can obtain sensitive cloud metadata or overwrite LLM provider configuration and API keys with values they control.
7. Alternatively, the attacker can initiate OAuth device-code flows via SSRF to acquire persistent access tokens.
8. These persistent access tokens are then stored in the `auth.json` file, granting the attacker persistent access to the compromised system or associated services.

## Impact

The successful exploitation of CVE-2026-58122 carries severe consequences, reflected in its CVSS v3.1 Base Score of 9.1. Attackers can gain unauthorized access to internal network resources and cloud environments. This includes the potential exfiltration of sensitive cloud metadata, compromise of LLM provider configurations, and theft of API keys, which can lead to further unauthorized access to services and data. The ability to acquire persistent access tokens stored in `auth.json` allows for long-term compromise and control over affected systems or associated third-party integrations, resulting in data breaches, service disruptions, and potentially complete system takeover.

## Recommendation

* Patch CVE-2026-58122 by upgrading Hermes WebUI to version 0.51.307 or later immediately to remediate the authentication bypass vulnerability.
* Deploy the provided Sigma rule to your SIEM solution to detect suspicious `X-Forwarded-For` header manipulation attempts targeting onboarding endpoints.
* Implement Web Application Firewall (WAF) rules to inspect and filter `X-Forwarded-For` headers for suspicious loopback addresses or unusual patterns, especially for external-facing "onboarding endpoints."
* Harden internal network segregation and endpoint security to limit the impact of successful SSRF attacks, particularly by restricting access to cloud metadata endpoints and sensitive configuration files like `auth.json`.
