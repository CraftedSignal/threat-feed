---
title: AVideo Unauthenticated Access to Payment Log DataTables Endpoints
slug: 2024-01-29-avideo-auth-bypass
description: AVideo is vulnerable to unauthenticated access to multiple `list.json.php` endpoints due to missing authorization checks, allowing attackers to retrieve sensitive payment transaction records, including PayPal billing agreement IDs, Express Checkout tokens, Authorize.Net webhook payloads, and Bitcoin payment records, leading to financial data exposure and potential PII leakage.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - avideo
  - authentication-bypass
  - payment-data-leak
vendors:
  - AVideo
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-wprj-9cvc-5w37
iocs:
  - type: url
    value: https://target.com/plugin/PayPalYPT/View/PayPalYPT_log/list.json.php
  - type: url
    value: https://target.com/plugin/AuthorizeNet/View/Anet_webhook_log/list.json.php
  - type: url
    value: https://target.com/plugin/BTCPayments/View/Btc_payments/list.json.php
ioc_counts:
  url: 3
rules:
  - title: AVideo Unauthenticated Access to list.json.php
    description: Detects unauthenticated requests to vulnerable list.json.php endpoints in AVideo plugins.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: AVideo Sensitive Data Exposure via Unauthenticated Endpoint
    description: Detects potential sensitive data exposure by monitoring network traffic for specific keywords indicating sensitive data being transmitted from AVideo list.json.php endpoints.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

AVideo, a video sharing platform, contains a critical vulnerability affecting multiple payment plugins. The vulnerability stems from the lack of authentication checks on `list.json.php` endpoints, which expose sensitive payment transaction data. This oversight allows unauthenticated attackers to retrieve payment records from PayPal, Authorize.Net, and Bitcoin payment providers. The issue mirrors a previously patched vulnerability in the Scheduler plugin (GHSA-j724-5c6c-68g5) but was not consistently applied across all affected endpoints. A total of 21 `list.json.php` endpoints remain vulnerable. The affected version is <= 26.0. This vulnerability poses a significant threat to AVideo users, potentially leading to financial data theft and unauthorized access to sensitive information.

## Attack Chain

1.  An unauthenticated attacker identifies a vulnerable AVideo instance.
2.  The attacker crafts a GET request to a vulnerable `list.json.php` endpoint, such as `plugin/PayPalYPT/View/PayPalYPT_log/list.json.php`.
3.  The AVideo server processes the request without authentication and executes the associated PHP script.
4.  The script queries the database, retrieving all records from the corresponding table (e.g., `PayPalYPT_log`).
5.  The server returns a JSON-encoded response containing the retrieved data, including sensitive payment information.
6.  The attacker parses the JSON response to extract PayPal agreement IDs, Express Checkout tokens, Authorize.Net webhook payloads, or Bitcoin transaction details.
7.  The attacker uses the extracted tokens or payment information for malicious purposes, such as payment manipulation or account correlation.

## Impact

Successful exploitation of this vulnerability leads to significant data exposure. Attackers can retrieve all payment transaction records across PayPal, Authorize.Net, and Bitcoin payment providers. This includes sensitive data such as PayPal Express Checkout tokens and billing agreement IDs, potentially enabling payment manipulation or account correlation. Transaction records contain user ID mappings, payment amounts, and full API responses that may include payer email addresses and names. The scope is broad, affecting 21 `list.json.php` endpoints, also exposing live streaming server infrastructure and user connection data. No authentication or user interaction is required.

## Recommendation

*   Apply the provided code snippet to all unprotected `list.json.php` endpoints to enforce authentication checks using `User::isAdmin()` as detailed in the advisory's recommended fix.
*   Monitor web server access logs for requests to `list.json.php` endpoints located within AVideo plugin directories using the rule `AVideo Unauthenticated Access to list.json.php`.
*   Inspect network traffic for sensitive data being transmitted in cleartext from the vulnerable endpoints, such as PayPal tokens, using the rule `AVideo Sensitive Data Exposure via Unauthenticated Endpoint`.
