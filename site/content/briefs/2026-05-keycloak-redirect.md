---
title: Keycloak Open Redirect Vulnerability (CVE-2026-7504)
slug: 2026-05-keycloak-redirect
description: A vulnerability in Keycloak's URL validation allows attackers to redirect users to unauthorized URLs by exploiting discrepancies in the handling of the user-info component within URLs, potentially leading to sensitive information exposure.
date: "2026-05-19T12:17:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - open-redirect
  - keycloak
  - cve
  - cloud
vendors:
  - Red Hat
products:
  - Keycloak
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7504
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7504
  - CVE-2026-7504
rules:
  - title: Detect CVE-2026-7504 Keycloak Redirect Attempt
    description: Detects CVE-2026-7504 exploitation — An attempt to exploit the Keycloak open redirect vulnerability by detecting multiple '@' characters in the redirect_uri parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Keycloak Wildcard Redirect URI Configuration
    description: Detects a Keycloak client configured with a wildcard (*) in the 'Valid Redirect URIs' field, which is a prerequisite for CVE-2026-7504 exploitation.  This requires access to Keycloak server logs or configuration files.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - file_event
      - linux
rules_count: 2
---

CVE-2026-7504 describes a flaw in Keycloak's URL validation logic during redirect operations. This vulnerability allows an attacker to craft malicious requests that bypass URL validation, redirecting users to unauthorized URLs. This can lead to the exposure of sensitive information or enable further attacks. The vulnerability specifically impacts Keycloak clients configured with a wildcard (*) in the "Valid Redirect URIs" field. Successful exploitation requires user interaction, making it necessary for a user to click on a specially crafted link. The issue arises from inconsistencies in how Keycloak and the Java URI implementation process the user-info component of a URL.

## Attack Chain

1. The attacker identifies a Keycloak instance with a wildcard (*) in the "Valid Redirect URIs" configuration.
2. The attacker crafts a malicious URL with multiple @ characters in the user-info section, such as `https://attacker.com@@example.com`.
3. The victim user receives the malicious URL via phishing or other social engineering techniques.
4. The victim clicks on the malicious link, initiating a request to the Keycloak server.
5. Keycloak's URL validation logic fails to properly parse the user-info component due to the multiple @ characters. The Java URI implementation contributes to this failure.
6. Keycloak falls back to the wildcard comparison for redirect URI validation, incorrectly permitting the malicious redirect.
7. The Keycloak server redirects the user to the attacker-controlled URL (`attacker.com`).
8. The attacker can then potentially steal sensitive information or conduct further malicious activities, such as session hijacking or credential harvesting.

## Impact

Successful exploitation of CVE-2026-7504 allows an attacker to redirect users to arbitrary, attacker-controlled websites. This can result in the theft of user credentials, session hijacking, or the exposure of sensitive information. Given a CVSS v3.1 base score of 8.1, the vulnerability presents a significant risk to Keycloak deployments with wildcard redirect URI configurations. The number of victims and the extent of the damage depend on the attacker's objectives and the sensitivity of the data accessible via the redirected URL.

## Recommendation

*   Deploy the Sigma rule "Detect CVE-2026-7504 Keycloak Redirect Attempt" to detect suspicious requests with multiple '@' characters in the redirect URI within your web server logs.
*   Review Keycloak client configurations and replace wildcard (*) entries in the "Valid Redirect URIs" field with explicit, specific URIs to mitigate the vulnerability.
*   Educate users to be cautious of suspicious links and to verify the legitimacy of URLs before clicking on them, especially those related to authentication or login processes.
