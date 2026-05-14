---
title: FlowiseAI Exposes Basic Auth Credentials via API
slug: 2026-05-flowiseai-basic-auth
description: FlowiseAI exposes a basic authentication endpoint without rate limiting, allowing attackers to brute-force credentials and gain unauthorized access to the application.
date: "2026-05-14T14:55:26Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - brute-force
  - flowiseai
vendors:
  - FlowiseAI
products:
  - flowise (<= 3.1.1)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
references:
  - https://github.com/advisories/GHSA-php6-83fg-gw3g
rules:
  - title: Detect FlowiseAI Basic Auth Brute Force Attempts
    description: Detects potential brute force attempts against the FlowiseAI basic authentication endpoint by monitoring the number of failed login attempts from a single IP address within a short time frame.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - webserver
  - title: Detect FlowiseAI Successful Basic Auth
    description: Detects successful authentication to the FlowiseAI basic authentication endpoint.
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - webserver
rules_count: 2
---

FlowiseAI, a low-code platform for building AI applications, contains a vulnerability in its basic authentication mechanism. Specifically, the `checkBasicAuth` endpoint validates credentials in plaintext without rate limiting, making it susceptible to brute-force attacks. The vulnerability, present in versions 3.1.1 and earlier, stems from the lack of rate limiting and the use of non-constant time comparison. The endpoint also returns distinct messages for successful and failed attempts, enabling attackers to enumerate valid usernames. Exploitation allows unauthorized access to the application's functionalities and data.

## Attack Chain

1.  Attacker identifies the `checkBasicAuth` endpoint, typically `/api/v1/checkBasicAuth`, which is used for basic authentication.
2.  The attacker crafts an HTTP POST request to the `checkBasicAuth` endpoint, including a username and password in the request body.
3.  The server receives the request and retrieves the username and password from the request body.
4.  The server compares the provided username and password directly with the values stored in the `FLOWISE_USERNAME` and `FLOWISE_PASSWORD` environment variables using the JavaScript `===` operator.
5.  If the credentials match, the server responds with a JSON message indicating "Authentication successful".
6.  If the credentials do not match, the server responds with a different JSON message indicating "Authentication failed". This allows enumeration.
7.  The attacker iteratively sends multiple requests with different username and password combinations, exploiting the lack of rate limiting to brute-force the credentials.
8.  Upon successful authentication, the attacker gains unauthorized access to the FlowiseAI application and its resources.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass authentication and gain unauthorized access to FlowiseAI applications. This can lead to data breaches, unauthorized modification of AI workflows, and potential compromise of sensitive information processed by the AI models. Given the lack of rate limiting, even relatively weak passwords can be compromised through brute-force attacks. This issue affects FlowiseAI installations up to version 3.1.1.

## Recommendation

*   Implement rate limiting on the `/api/v1/checkBasicAuth` endpoint to prevent brute-force attacks.
*   Deploy the Sigma rule "Detect FlowiseAI Basic Auth Brute Force Attempts" to identify suspicious activity on the vulnerable endpoint.
*   Modify the authentication logic to use constant-time comparison functions to mitigate timing attacks, as described in the overview section of this brief.
*   Change the application to return generic error messages to prevent username enumeration, as described in the overview section of this brief.
*   Upgrade FlowiseAI to a version beyond 3.1.1 where this vulnerability is resolved.
