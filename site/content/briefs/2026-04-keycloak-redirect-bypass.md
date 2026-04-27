---
title: Keycloak Redirect URI Bypass Vulnerability (CVE-2026-3872)
slug: 2026-04-keycloak-redirect-bypass
description: CVE-2026-3872 is a vulnerability in Keycloak that allows an attacker controlling a path on the same web server to bypass URI redirect validation using a wildcard, potentially leading to access token theft and information disclosure.
date: "2026-04-02T13:16:26Z"
severities:
  - medium
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
ioc_counts:
  email: 1
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

CVE-2026-3872 is a security flaw found in Keycloak, a popular open-source identity and access management solution. This vulnerability allows a malicious actor who has control over another path on the same web server hosting Keycloak to circumvent the allowed path restrictions in redirect URIs that use a wildcard. By exploiting this weakness, an attacker can potentially redirect a user to a malicious site after authentication, intercept the access token, and gain unauthorized access to the…
