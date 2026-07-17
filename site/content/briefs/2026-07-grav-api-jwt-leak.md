---
title: Grav API Plugin Vulnerability Exposes JWT Access Tokens via URL Parameter
slug: 2026-07-grav-api-jwt-leak
description: The Grav API plugin (getgrav/grav-plugin-api) before version 1.0.0-rc.16 is vulnerable to sensitive information exposure, accepting JWT access tokens via the '?token=' URL query parameter, causing these tokens to be logged in web server access logs, browser history, and potentially leaked through Referer headers, proxy, or CDN logs, which allows an attacker to gain unauthorized API access, read configuration and user data, create new admin accounts, modify system settings, and delete pages.
date: "2026-07-17T02:41:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - web
  - api
  - jwt
  - information-exposure
  - grav
vendors:
  - getgrav
products:
  - Grav API plugin (< 1.0.0-rc.16)
  - grav-plugin-api (< 1.0.0-rc.16)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Because tokens are embedded in URLs, they are logged verbatim in web server access logs, leaked via the Referer header, stored in browser history, and captured by upstream proxy and CDN logs, exposing valid admin access tokens.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: A leaked token grants unauthorized API access, including reading configuration and user data, creating admin accounts, modifying system settings, and deleting pages.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: A leaked token grants unauthorized API access, including ... creating admin accounts
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: A leaked token grants unauthorized API access, including reading configuration and user data
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: A leaked token grants unauthorized API access, including ... modifying system settings
    confidence_band: med
  - tactic_id: TA0008
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: A leaked token grants unauthorized API access, including ... deleting pages.
    confidence_band: high
cves:
  - id: CVE-2026-62386
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62386
rules:
  - title: Detects CVE-2026-62386 Exploitation - Grav API JWT Token in URL
    description: Detects CVE-2026-62386 exploitation where a JWT token is passed in the URL query parameter for Grav API requests, indicating token exposure or exploitation attempt. This pattern might appear in web server access logs.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552
    data_sources:
      - webserver
rules_count: 1
---

A critical vulnerability, tracked as CVE-2026-62386, has been identified in the Grav API plugin (getgrav/grav-plugin-api) affecting all versions prior to 1.0.0-rc.16. This flaw allows JWT access tokens to be submitted and processed via the `?token=` URL query parameter across all API routes. This method of token submission inherently exposes sensitive admin access tokens, as they are logged verbatim in web server access logs, stored in browser history, and can be leaked via the Referer HTTP header or captured by upstream proxy and CDN logs. This widespread exposure of valid admin tokens grants unauthorized individuals full API access, enabling them to read sensitive configuration files and user data, create new administrator accounts, modify critical system settings, and delete pages. The vulnerability poses a significant risk to the integrity and confidentiality of Grav-based websites.

## Attack Chain

1. An attacker identifies a Grav API endpoint susceptible to the `?token=` parameter vulnerability.
2. A valid JWT admin access token for the Grav API is acquired through passive means (e.g., from web server access logs, browser history, proxy/CDN logs, or HTTP Referer header leakage).
3. The attacker constructs a malicious HTTP request to a Grav API endpoint, embedding the leaked JWT token in the `?token=` URL query parameter.
4. The Grav API processes the request, authenticating the attacker with the legitimate admin token.
5. The attacker proceeds to read sensitive configuration and user data from the Grav system via authenticated API calls.
6. Utilizing API functionality, the attacker creates new administrative user accounts to establish persistence within the Grav environment.
7. The attacker modifies critical system settings or configuration parameters via API calls to further control the application.
8. Finally, the attacker deletes content, such as pages, or performs other destructive actions, achieving unauthorized control and data manipulation within the Grav instance.

## Impact

The successful exploitation of CVE-2026-62386 can lead to severe consequences for affected Grav instances. Unauthorized individuals gaining access to valid admin JWT tokens can bypass authentication mechanisms and achieve full control over the Grav API. This can result in the complete compromise of data confidentiality through the reading of sensitive configuration and user data, including potentially private content. Furthermore, the ability to create new administrator accounts and modify system settings grants attackers persistent access and potential privilege escalation, allowing them to subvert the website's functionality and integrity. The deletion of pages represents a direct impact on data availability and can lead to significant reputational damage or operational disruption.

## Recommendation

* Patch CVE-2026-62386 immediately by upgrading the Grav API plugin to version 1.0.0-rc.16 or higher.
* Review web server access logs, proxy logs, and CDN logs for any instances of `?token=` parameters in URL paths, which could indicate prior or ongoing token exposure.
* Configure web server logging to filter or redact sensitive URL query parameters (specifically `token=`) to prevent future leakage, even after patching.
* Deploy the Sigma rule provided in this brief to your SIEM to detect attempts to exploit this vulnerability or unusual token usage patterns.
