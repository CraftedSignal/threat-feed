---
title: OpenMage LTS Weak API Session ID Vulnerability Leads to Session Hijacking
slug: 2024-01-openmage-session-hijacking
description: OpenMage LTS version 20.16.0 and earlier has a critical vulnerability in the XML-RPC/SOAP API session ID generation, which uses a predictable MD5 hash of time-derived inputs, allowing attackers to brute-force and hijack active API sessions for data exfiltration, order fraud, and supply chain manipulation.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - session hijacking
  - API vulnerability
  - brute-force attack
vendors:
  - OpenMage
products:
  - magento-lts (<= 20.16.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://github.com/advisories/GHSA-2cwr-gcf9-pvxr
iocs:
  - type: url
    value: http://demo.openmage.org/
  - type: url
    value: https://github.com/OpenMage/magento-lts/blob/main/app/code/core/Mage/Api/Model/Session.php
ioc_counts:
  url: 2
rules:
  - title: Detect OpenMage API Session Hijacking Attempts via XML-RPC
    description: Detects attempts to exploit the OpenMage API session hijacking vulnerability by monitoring POST requests to the `/api/xmlrpc/` endpoint with a large number of requests from the same IP address within a short timeframe, indicating potential brute-force activity.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1550.003
    data_sources:
      - webserver
      - linux
  - title: Detect OpenMage API Session Hijacking - Resources Method
    description: Detects successful session hijacking attempts by monitoring POST requests to the `/api/xmlrpc/` endpoint using the `resources` method after successful login.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1550.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenMage LTS, a fork of Magento, is vulnerable to session hijacking due to its insecure method of generating API session IDs. Specifically, versions 20.16.0 and earlier generate session IDs using an MD5 hash of time-derived inputs (timestamp, microsecond, and LCG state), rather than a cryptographically secure random number generator. This vulnerability exists in the `Mage_Api_Model_Session.php` file within the `start()` method.  The lack of sufficient entropy in the session ID makes it predictable and susceptible to brute-force attacks, especially given the absence of API rate limiting. An attacker can exploit this vulnerability to gain unauthorized access to user accounts and perform malicious actions. This vulnerability affects all legacy API surfaces including XML-RPC, SOAP v1, SOAP v2, and legacy REST APIs.

## Attack Chain

1.  Attacker observes a victim authenticating to the `/api/xmlrpc/` endpoint, capturing the Unix timestamp of the login event via network timing or exposed logs.
2.  The attacker estimates the microsecond portion of the timestamp based on observed network latency or other side-channel information.
3.  The attacker reconstructs the MD5 hash format using the known timestamp and the estimated microsecond window.
4.  The attacker bounds the LCG float component based on server PID ranges (if known or leaked via `/server-status`).
5.  The attacker generates a candidate pool of MD5 hashes based on the reconstructed format and LCG variations.
6.  The attacker sends a series of crafted HTTP POST requests to the `/api/xmlrpc/` endpoint, each containing a different candidate session ID within the `<methodCall><params><param><value><string>{CANDIDATE_SESSION_ID}</string></value></param></params></methodCall>` XML structure.
7.  The attacker monitors the HTTP responses for a non-fault response (HTTP 200 containing data), indicating a successful session hijack.
8.  Upon successful hijack, the attacker uses the valid session ID to access privileged API endpoints, such as those for managing product catalogs, customer data, or orders, to perform malicious actions such as data exfiltration, order fraud, or inventory manipulation.

## Impact

Successful exploitation of this vulnerability allows an attacker to hijack active API sessions, granting them full control over the compromised account.  This can lead to data exfiltration of customer PII, order history, and payment methods. Attackers can also manipulate orders by creating, canceling, or changing shipping addresses. Further, they can modify prices, inject malicious products, or zero out stock, leading to significant financial and operational damage. This vulnerability affects all legacy API protocols, including XML-RPC, SOAP v1, SOAP v2, and REST APIs.

## Recommendation

*   Apply the vendor-supplied patch to replace the time-derived token with a cryptographically secure random value, as described in the advisory by updating `app/code/core/Mage/Api/Model/Session.php` file.
*   Implement rate limiting on API endpoints like `/api/xmlrpc/` to prevent high-speed online brute-force attacks.
*   Monitor web server logs for unusual POST requests to the `/api/xmlrpc/`, `/api/soap/`, `/api/v2_soap/`, and `/api/rest/` endpoints using the Sigma rule provided to detect potential session hijacking attempts.
