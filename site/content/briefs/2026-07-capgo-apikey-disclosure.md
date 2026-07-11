---
title: Capgo API Key Information Disclosure Vulnerability (CVE-2026-56303)
slug: 2026-07-capgo-apikey-disclosure
description: An information disclosure vulnerability (CVE-2026-56303) in Capgo versions before 12.128.2 allows unauthenticated attackers to retrieve sensitive API key metadata, including user ID, mode, organization scoping, and expiration details, by exploiting a misconfigured PostgreSQL function via the `/rest/v1/rpc/find_apikey_by_value` endpoint.
date: "2026-07-11T14:20:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - information-disclosure
  - vulnerability
  - api-security
  - web-application
vendors:
  - Capgo
products:
  - Capgo (< 12.128.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can call this function via the /rest/v1/rpc/find_apikey_by_value endpoint
    confidence_band: high
cves:
  - id: CVE-2026-56303
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56303
  - https://github.com/Cap-go/capgo/security/advisories/GHSA-2xjq-h43m-592f
  - https://www.vulncheck.com/advisories/capgo-unauthenticated-api-key-metadata-disclosure-via-security-definer-rpc-function
rules:
  - title: Detects CVE-2026-56303 Exploitation Attempt - Capgo API Key Disclosure
    description: Detects CVE-2026-56303 exploitation - HTTP POST requests to the /rest/v1/rpc/find_apikey_by_value endpoint, which an unauthenticated attacker can call to retrieve sensitive API key metadata due to a misconfigured PostgreSQL function.
    platform: sigma
    severity: high
    tactics:
      - collection
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A critical information disclosure vulnerability, identified as CVE-2026-56303, exists in Capgo software versions prior to 12.128.2. This flaw stems from a misconfiguration within the `find_apikey_by_value` PostgreSQL function, which is marked with `SECURITY DEFINER` and is unexpectedly executable by the `anon` role. Unauthenticated attackers can exploit this by sending a specially crafted HTTP POST request to the `/rest/v1/rpc/find_apikey_by_value` endpoint. When a valid API key value is supplied, the vulnerable function retrieves and discloses sensitive API key metadata, including `user_id`, `mode`, `org scoping`, and `expiration details`. This vulnerability allows attackers to gather crucial information that could lead to unauthorized access, privilege escalation, or further targeted attacks against the Capgo instance and its associated services, posing a significant risk to data confidentiality.

## Attack Chain

1. **Vulnerability Identification**: An attacker identifies a Capgo instance running a version prior to 12.128.2, making it susceptible to CVE-2026-56303.
2. **Request Construction**: The attacker crafts an unauthenticated HTTP POST request specifically targeting the `/rest/v1/rpc/find_apikey_by_value` endpoint.
3. **API Key Provision**: The attacker includes a valid API key value within the body or parameters of the POST request, which may have been guessed, leaked, or brute-forced.
4. **Function Execution**: The Capgo application receives the request and, due to the `find_apikey_by_value` PostgreSQL function being marked `SECURITY DEFINER` and executable by the `anon` role, it executes the function with elevated privileges.
5. **Database Query**: The executed PostgreSQL function queries the underlying database for metadata associated with the provided API key.
6. **Information Disclosure**: The Capgo application retrieves the sensitive API key metadata, including `user_id`, `mode`, `org scoping`, and `expiration details`, from the database.
7. **Response Delivery**: The application includes this sensitive metadata in the HTTP response body, sending it back to the unauthenticated attacker.
8. **Data Collection and Abuse**: The attacker collects the disclosed API key metadata, which can then be used for unauthorized access, privilege escalation, or further targeted attacks against the Capgo instance or associated services.

## Impact

Successful exploitation of CVE-2026-56303 leads to the unauthorized disclosure of sensitive API key metadata. This includes critical information such as user identifiers, operational modes, organizational scope, and expiration details of API keys. While the vulnerability itself does not directly grant arbitrary code execution or full system compromise, the exposed API key metadata can be a crucial stepping stone for attackers to escalate privileges, gain unauthorized access to other systems or data, or circumvent security controls. The impact primarily involves confidentiality breaches, potentially affecting all data accessible via the compromised API keys within the Capgo environment. The number of potentially affected victims corresponds to the total number of Capgo instances running vulnerable versions.

## Recommendation

* Patch Capgo instances to version 12.128.2 or later immediately to remediate CVE-2026-56303.
* Deploy the Sigma rule titled "Detects CVE-2026-56303 Exploitation Attempt - Capgo API Key Disclosure" to your SIEM to monitor for exploitation attempts against the `/rest/v1/rpc/find_apikey_by_value` endpoint.
* Monitor web server access logs for repeated or unusual POST requests to the `/rest/v1/rpc/find_apikey_by_value` endpoint from untrusted sources or at abnormal frequencies.
