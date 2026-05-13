---
title: Systempay 1.0 Weak Crypto Allows Payment Signature Forging (CVE-2020-37168)
slug: 2026-05-systempay-key-forge
description: Systempay 1.0 contains a weak cryptographic implementation vulnerability (CVE-2020-37168) allowing attackers to brute-force the production secret key, forge payment signatures, and manipulate transaction amounts.
date: "2026-05-13T16:17:42Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - credential-access
  - ecommerce
  - payment-fraud
products:
  - Systempay 1.0
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2020-37168
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2020-37168
  - CVE-2020-37168
rules:
  - title: Detect Systempay Potential Key Brute-Force
    description: Detects CVE-2020-37168 exploitation - Attempts to brute-force the Systempay production secret key based on POST requests to the payment endpoint.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - persistence
    techniques:
      - T1555
    data_sources:
      - webserver
  - title: Detect Systempay Key Forge via Modified Payment
    description: Detects CVE-2020-37168 exploitation - Detects POST requests to the Systempay payment endpoint with suspicious modifications to payment parameters.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - integrity
    techniques:
      - T1555
    data_sources:
      - webserver
rules_count: 2
---

Systempay 1.0 suffers from a critical vulnerability, CVE-2020-37168, stemming from a weak cryptographic implementation in its payment signature generation. Attackers exploit this flaw by targeting the 16-character production secret key. This allows an attacker to forge valid payment signatures, potentially leading to unauthorized transaction amount modifications. This is particularly concerning for e-commerce platforms relying on Systempay 1.0 for payment processing, as it directly jeopardizes the integrity of financial transactions. Successful exploitation could result in significant financial losses and reputational damage. The vulnerability impacts all installations of Systempay version 1.0.

## Attack Chain

1.  Attacker intercepts a legitimate payment request sent to the Systempay payment endpoint. This request includes the payment form data and the associated payment signature.
2.  The attacker extracts the payment form data and the corresponding signature from the intercepted POST request.
3.  Attacker begins a brute-force attack to guess the 16-character production secret key used for payment signature generation.
4.  The attacker generates a candidate signature using the extracted payment form data and a guessed secret key. The attacker will then hash the result using SHA1.
5.  The attacker compares the generated signature with the original signature.
6.  If the generated signature matches the original signature, the attacker has successfully identified the correct production secret key.
7.  Using the discovered secret key, the attacker modifies the payment form data (e.g., transaction amount) to their advantage.
8.  The attacker generates a new, valid payment signature for the modified payment form data using the discovered secret key. The attacker then submits the forged payment request.

## Impact

Successful exploitation of CVE-2020-37168 allows attackers to forge valid payment signatures, enabling them to manipulate transaction amounts. This could lead to direct financial losses for merchants and customers. Given the severity (CVSS 9.8), organizations using Systempay 1.0 should consider this a high priority incident.

## Recommendation

*   Examine web server logs for unusual POST requests to the payment endpoint that may indicate signature brute-forcing (see the rule `Detect Systempay Potential Key Brute-Force`).
*   Since there is no patch available, consider migrating to a different payment processing platform or implementing a robust Web Application Firewall (WAF) with rate limiting to mitigate brute-force attempts.
*   Monitor network traffic for patterns associated with brute-force attempts against payment endpoints (see rule `Detect Systempay Key Forge via Modified Payment`).
*   Implement additional security measures, such as multi-factor authentication, to protect against unauthorized access to payment processing systems.
