---
title: Keycloak Redirect URI Bypass Vulnerability (CVE-2026-3872)
slug: 2026-04-keycloak-redirect-bypass
description: CVE-2026-3872 is a vulnerability in Keycloak that allows an attacker controlling a path on the same web server to bypass URI redirect validation using a wildcard, potentially leading to access token theft and information disclosure.
date: "2026-04-02T13:16:26Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - keycloak
  - redirect-uri-bypass
  - cve-2026-3872
  - authentication
  - authorization
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
cves:
  - id: CVE-2026-3872
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3872
  - https://access.redhat.com/security/cve/CVE-2026-3872
  - https://bugzilla.redhat.com/show_bug.cgi?id=2445988
rules:
  - title: Detect Keycloak Redirect URI Bypass Attempt
    description: Detects potential attempts to exploit the Keycloak redirect URI bypass vulnerability (CVE-2026-3872) by identifying suspicious patterns in HTTP request URIs.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Keycloak Authentication Redirection to External Domain
    description: Detects Keycloak authentication redirection attempts to domains that are not explicitly whitelisted, potentially indicating a phishing or redirect bypass attack.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1566.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-3872 is a security flaw found in Keycloak, a popular open-source identity and access management solution. This vulnerability allows a malicious actor who has control over another path on the same web server hosting Keycloak to circumvent the allowed path restrictions in redirect URIs that use a wildcard. By exploiting this weakness, an attacker can potentially redirect a user to a malicious site after authentication, intercept the access token, and gain unauthorized access to the user's resources. The vulnerability could lead to the disclosure of sensitive information and potentially compromise user accounts. This was published on April 2, 2026, and has a CVSS v3.1 score of 7.3.

## Attack Chain

1.  The attacker gains control of a path on the same web server hosting the Keycloak instance. This could be achieved through various means, such as exploiting a separate vulnerability in another application hosted on the server.
2.  The attacker crafts a malicious URL that exploits the wildcard redirect URI validation flaw in Keycloak. The crafted URL includes a redirect URI that bypasses the intended restrictions.
3.  A legitimate user initiates an authentication request to Keycloak, potentially through a vulnerable application relying on Keycloak for authentication.
4.  Keycloak processes the authentication request and, due to the vulnerability, accepts the attacker's crafted redirect URI as valid.
5.  Keycloak redirects the user to the attacker-controlled URL after successful authentication.
6.  The attacker's server captures the access token from the redirect URI.
7.  The attacker uses the stolen access token to impersonate the user and access protected resources.
8.  The attacker gains unauthorized access to sensitive information or performs actions on behalf of the user, leading to information disclosure or other malicious activities.

## Impact

Successful exploitation of CVE-2026-3872 can lead to the theft of access tokens, enabling unauthorized access to user accounts and sensitive data. This could result in the compromise of user privacy, financial loss, or reputational damage for organizations relying on affected Keycloak instances. The impact is significant because Keycloak is used across various sectors to secure web applications and APIs.

## Recommendation

*   Apply the security patches or updates provided by Red Hat for Keycloak to address CVE-2026-3872. Refer to the Red Hat advisory linked in the references for specific instructions.
*   Deploy the provided Sigma rule to detect exploitation attempts of CVE-2026-3872 based on suspicious redirect URIs in web server logs.
*   Review and harden the configuration of redirect URIs in Keycloak, avoiding the use of wildcards where possible and implementing stricter validation rules.
*   Monitor web server logs for suspicious activity related to redirect URIs, looking for unusual patterns or attempts to access unauthorized resources.
