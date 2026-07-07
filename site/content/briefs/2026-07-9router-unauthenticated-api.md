---
title: Critical Unauthenticated API Vulnerabilities in 9Router Leading to Data Leak and RCE Risk
slug: 2026-07-9router-unauthenticated-api
description: Multiple critical unauthenticated API vulnerabilities in 9Router versions up to 0.4.41 allow an attacker to perform full CRUD operations on provider connections, leak plaintext API keys, and access sensitive conversation history, posing risks of data exfiltration and denial of service.
date: "2026-07-06T21:30:03Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - web-vulnerability
  - api-security
  - data-exfiltration
  - credential-access
  - denial-of-service
  - unauthenticated-access
vendors:
  - 9Router
products:
  - 9Router <= 0.4.41
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Multiple critical API security vulnerabilities were discovered in 9Router's Next.js dashboard. The `/api/providers` endpoints lack authentication entirely, allowing anyone to create, read, update, and delete provider connections.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: The endpoint returns complete API key strings (e.g., `sk-...`) in plaintext alongside usage data per key, enabling unauthorized use of connected AI provider accounts.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
    evidence: The endpoint returns complete API key strings (e.g., `sk-...`) in plaintext alongside usage data per key, enabling unauthorized use of connected AI provider accounts.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Defense Evasion
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The endpoint returns complete API key strings (e.g., `sk-...`) in plaintext alongside usage data per key, enabling unauthorized use of connected AI provider accounts.
    confidence_band: med
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Delete all providers — cause complete denial of service
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-vjc7-jrh9-9j86
rules:
  - title: Detect 9Router Unauthenticated Provider CRUD Attempts
    description: Detects unauthenticated attempts to create, modify, or delete 9Router provider connections via /api/providers endpoint due to a lack of authentication.
    platform: sigma
    severity: critical
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
      - T1589.001
    data_sources:
      - webserver
  - title: Detect 9Router Unauthenticated API Key Leakage Attempt
    description: Detects unauthenticated attempts to access /api/usage/stats in 9Router, which exposes full plaintext API keys.
    platform: sigma
    severity: critical
    tactics:
      - collection
      - credential_access
    techniques:
      - T1592.002
    data_sources:
      - webserver
  - title: Detect 9Router Unauthenticated Conversation History Leakage Attempt
    description: Detects unauthenticated attempts to access /api/usage/request-details or /api/usage/request-logs in 9Router, leading to sensitive conversation data exposure.
    platform: sigma
    severity: critical
    tactics:
      - collection
    techniques:
      - T1589.001
      - T1590.001
    data_sources:
      - webserver
rules_count: 3
---

Critical API security vulnerabilities have been identified in 9Router's Next.js dashboard, impacting versions up to 0.4.41. These flaws stem from a lack of authentication middleware on several API endpoints, making them fully accessible to unauthenticated attackers. Specifically, the `/api/providers` endpoints permit complete Create, Read, Update, and Delete (CRUD) operations on all provider connections, enabling an attacker to manipulate or destroy configurations, redirect traffic, or capture credentials. Additionally, the `/api/usage/stats` endpoint exposes full plaintext API keys, while `/api/usage/request-logs` and `/api/usage/request-details` disclose all users' request history and sensitive conversation contents, including system prompts and user messages. This combination of vulnerabilities allows for widespread data exfiltration, credential compromise, and potential denial of service or traffic hijacking.

## Attack Chain

1.  An unauthenticated attacker sends an HTTP GET request to `https://<host>/api/providers` to list all configured provider connections, obtaining partial credentials and account IDs.
2.  The attacker sends an HTTP POST request to `https://<host>/api/providers` with a malicious payload to create a new, attacker-controlled provider connection (e.g., `{"provider":"openai","authType":"apikey","name":"rogue","apiKey":"sk-attacker-controlled"}`).
3.  The attacker sends an HTTP PUT request to `https://<host>/api/providers/<existing-uuid>` to modify an existing provider's configuration, potentially replacing legitimate API keys with their own to redirect traffic or exfiltrate data.
4.  The attacker sends an HTTP DELETE request to `https://<host>/api/providers/<existing-uuid>` to delete critical provider connections, leading to denial of service for legitimate users.
5.  The attacker sends an HTTP GET request to `https://<host>/api/usage/stats` to retrieve a list of all plaintext API keys, per-account usage data, and cost information.
6.  The attacker sends an HTTP GET request to `https://<host>/api/usage/request-logs` to obtain paginated request logs containing timestamps, models, providers, and user emails.
7.  The attacker retrieves individual conversation details by sending an HTTP GET request to `https://<host>/api/usage/request-details/<request-uuid>`, exposing full conversation turns, including system prompts and sensitive user messages.
8.  The attacker leverages the stolen API keys and conversation data for further malicious activities, such as unauthorized access to AI provider accounts or social engineering.

## Impact

The identified vulnerabilities have critical consequences. An attacker can add malicious providers to intercept all prompts and responses, modify existing providers to hijack legitimate traffic, or delete all providers to cause a complete denial of service. The compromise extends to a full API key leak via `/api/usage/stats`, enabling unauthorized use of connected AI provider accounts. Most critically, the `/api/usage/request-details` endpoint exposes complete conversation histories, including highly sensitive system prompts, user messages, and assistant responses, leading to severe privacy breaches and potential exfiltration of proprietary or confidential information processed by AI models.

## Recommendation

*   Prioritize patching 9Router instances to a version greater than 0.4.41 immediately.
*   Deploy the provided Sigma rules to your SIEM solution and tune them for your environment to detect attempts to exploit these vulnerabilities against `/api/providers`, `/api/usage/stats`, and `/api/usage/request-details`.
*   Review web server access logs for any suspicious unauthenticated POST, PUT, or DELETE requests to `/api/providers` endpoints as well as GET requests to `/api/usage/stats` or `/api/usage/request-details` originating from unusual IP addresses.
*   Implement strong authentication and authorization controls for all sensitive API endpoints in your environment, especially those related to configuration and data access.
