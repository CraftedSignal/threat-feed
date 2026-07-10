---
title: Flowise Public Chatflow Endpoint Exposes Sensitive Data
slug: 2024-01-flowise-leak
description: Flowise versions 3.0.13 and earlier expose sensitive information, including credential IDs, plaintext API keys, and passwords, through the `GET /api/v1/public-chatflows/:id` endpoint, leading to account compromise and revealing internal architecture details.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - flowise
  - credential-leak
  - api-security
vendors:
  - Flowise
products:
  - Flowise
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
references:
  - https://github.com/advisories/GHSA-w47f-j8rh-wx87
rules:
  - title: Detect Flowise Public Chatflow Data Exposure
    description: Detects attempts to access the Flowise public chatflow endpoints which may expose sensitive data in vulnerable versions.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1592
    data_sources:
      - webserver
      - linux
  - title: Detect Sensitive Keywords in Flowise Public Chatflow Responses
    description: Detects responses from Flowise public chatflow endpoints containing potential sensitive keywords indicating data exposure.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1592
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Flowise, an open-source low-code platform for building AI orchestration flows, is vulnerable to sensitive information disclosure. Specifically, versions 3.0.13 and earlier fail to sanitize the `flowData` returned by the `GET /api/v1/public-chatflows/:id` and `GET /api/v1/public-chatbotConfig/:id` endpoints. This oversight exposes credential IDs, plaintext API keys, passwords, and internal node configurations to unauthorized users. The `sanitizeFlowDataForPublicEndpoint` function, intended to mitigate this issue, is either missing or not implemented correctly in the affected versions, leading to the leakage of sensitive information when a chatflow is marked as public. This vulnerability allows attackers to compromise third-party accounts and gain insights into the application's architecture.

## Attack Chain

1.  An attacker identifies a Flowise instance running a vulnerable version (<= 3.0.13).
2.  The attacker discovers a public chatflow by guessing or enumerating available chatflow IDs.
3.  The attacker sends a `GET` request to `/api/v1/public-chatflows/:id` or `/api/v1/public-chatbotConfig/:id`, where `:id` is the ID of the public chatflow.
4.  The Flowise server responds with the full chatflow object, including the raw `flowData`.
5.  The `flowData` contains unsanitized sensitive information such as credential IDs, plaintext API keys, and passwords stored within node configurations.
6.  The attacker extracts the leaked credential IDs and uses them to attempt OAuth2 token theft.
7.  The attacker extracts API keys and passwords, using them to compromise third-party accounts or services integrated with the Flowise application.
8.  The attacker analyzes the node configurations to understand the internal architecture and endpoint URLs of the Flowise application, potentially identifying further vulnerabilities.

## Impact

Successful exploitation of this vulnerability can lead to several critical consequences. Credential IDs leaked through the API can be used to steal OAuth2 tokens. Plaintext API keys and passwords within the `flowData` enable direct compromise of third-party accounts integrated with Flowise. The exposure of internal node configurations and endpoint URLs provides attackers with valuable information to further compromise the Flowise application and its connected services. While the specific number of affected instances is unknown, any Flowise deployment using publicly accessible chatflows with sensitive data in `flowData` is at risk.

## Recommendation

*   Deploy the Sigma rule `Detect Flowise Public Chatflow Data Exposure` to identify instances attempting to access public chatflow endpoints (logsource: `webserver`).
*   Immediately upgrade Flowise instances to a version greater than 3.0.13 that includes the `sanitizeFlowDataForPublicEndpoint` function and ensures its proper implementation on both `public-chatflows` and `public-chatbotConfig` endpoints (reference: github advisory).
*   Rotate all API keys and passwords stored within Flowise `flowData` of publicly accessible chatflows (reference: overview).
*   Audit all existing public chatflows for sensitive data and remove any exposed credentials or secrets (reference: attack chain).
