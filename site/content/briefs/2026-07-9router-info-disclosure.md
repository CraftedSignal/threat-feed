---
title: 9Router Unauthenticated Information Disclosure (CVE-2026-62328)
slug: 2026-07-9router-info-disclosure
description: An unauthenticated information disclosure vulnerability in 9Router through version 0.4.41 allows remote attackers to access sensitive user data by querying unprotected API endpoints like `/request-logs` and `/request-details` to enumerate paginated request logs and retrieve complete AI conversation histories, including system prompts, user messages, assistant responses, tool calls, and user email addresses, due to a lack of authentication middleware.
date: "2026-07-13T22:32:50Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - information-disclosure
  - vulnerability
  - web-application
vendors:
  - 9Router
products:
  - 9Router (< 0.4.42)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: 9Router through version 0.4.41 contain an unauthenticated information disclosure vulnerability that allows remote attackers to access sensitive user data by sending requests to unprotected API endpoints.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: Attackers can enumerate paginated request logs and retrieve complete AI conversation histories including system prompts, user messages, assistant responses, tool calls, and user email addresses by querying the request-logs and request-details API routes.
    confidence_band: high
cves:
  - id: CVE-2026-62328
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62328
rules:
  - title: Detects CVE-2026-62328 Exploitation - Unauthenticated Request Logs Access
    description: Detects CVE-2026-62328 exploitation - unauthenticated HTTP GET requests to the /request-logs endpoint of 9Router, indicating an attempt to access sensitive logs.
    platform: sigma
    severity: high
    tactics:
      - collection
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-62328 Exploitation - Unauthenticated Request Details Access
    description: Detects CVE-2026-62328 exploitation - unauthenticated HTTP GET requests to the /request-details endpoint of 9Router, indicating an attempt to retrieve sensitive AI conversation data.
    platform: sigma
    severity: high
    tactics:
      - collection
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A critical unauthenticated information disclosure vulnerability, tracked as CVE-2026-62328, affects 9Router software versions up to and including 0.4.41. Remote attackers can exploit this flaw to gain unauthorized access to sensitive user data, including complete AI conversation histories and associated user email addresses. The vulnerability stems from a lack of authentication middleware on specific API endpoints, namely `/request-logs` and `/request-details`. This allows unauthenticated users to enumerate paginated request logs and then retrieve detailed AI conversation data, such as system prompts, user messages, assistant responses, and tool calls. This exposure of sensitive data poses a significant privacy and security risk to users of affected 9Router installations.

## Attack Chain

1. Attacker discovers an internet-accessible 9Router instance running an affected version (0.4.41 or earlier).
2. Attacker sends an unauthenticated HTTP GET request to the `/request-logs` API endpoint (e.g., `GET /request-logs`).
3. The vulnerable 9Router instance responds with paginated request logs, which include `requestId` values for past conversations, due to the lack of proper authentication controls.
4. Attacker parses the received logs to extract valid `requestId` values associated with user interactions.
5. Attacker crafts and sends subsequent unauthenticated HTTP GET requests to the `/request-details` API endpoint, appending an extracted `requestId` as a query parameter (e.g., `GET /request-details?requestId=ABC-123`).
6. The 9Router instance, still lacking authentication middleware for this endpoint, responds with the complete AI conversation history corresponding to the `requestId`. This data includes system prompts, user messages, assistant responses, tool calls, and associated user email addresses.
7. Attacker continuously queries various `requestId` values to collect a large volume of sensitive user data, leading to unauthorized data exfiltration.

## Impact

Successful exploitation of CVE-2026-62328 leads to the unauthorized disclosure of highly sensitive user information. Attackers can retrieve full AI conversation histories, including private discussions, proprietary system prompts, and detailed interactions between users and the AI. Crucially, user email addresses are also exposed, increasing the risk of targeted phishing, identity theft, or further malicious activities. The number of potential victims corresponds to the user base of affected 9Router instances, with the scope of data exposure depending on the volume of logged requests. The core damage involves a severe breach of data confidentiality and user privacy.

## Recommendation

* Patch CVE-2026-62328 immediately by upgrading 9Router to version 0.4.42 or later.
* Deploy the provided Sigma rules to your SIEM to detect attempts to access the vulnerable API endpoints.
* Enable comprehensive web server logging for HTTP requests, particularly for `cs-uri-stem` and `cs-method`, to activate the detection rules.
* Review web server access logs for any unauthenticated or suspicious GET requests to `/request-logs` or `/request-details` from external IP addresses.
