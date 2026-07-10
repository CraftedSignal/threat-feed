---
title: Eclipse Jetty JASPIAuthenticator ThreadLocal Privilege Escalation (CVE-2026-5795)
slug: 2024-01-jetty-privesc
description: Eclipse Jetty is vulnerable to broken access control and privilege escalation due to improper handling of ThreadLocal variables within the JASPIAuthenticator, potentially leading to unauthorized access.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege escalation
  - webserver
  - cve-2026-5795
vendors:
  - Eclipse
products:
  - Jetty
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-5795
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5795
  - https://github.com/jetty/jetty.project/security/advisories/GHSA-r7p8-xq5m-436c
  - https://gitlab.eclipse.org/security/cve-assignment/-/issues/92
rules:
  - title: Detect Jetty Authentication Errors
    description: Detects HTTP 500 errors potentially related to authentication failures within Jetty, which could precede or be a symptom of CVE-2026-5795 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect Multiple Authentication Attempts from Single IP
    description: Detects a high number of failed authentication attempts from a single IP address within a short period, indicating potential brute-force or exploitation attempts against Jetty's authentication mechanism.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1110.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-5795 describes a vulnerability in Eclipse Jetty related to improper handling of ThreadLocal variables within the `JASPIAuthenticator` class. When initiating authentication checks, the `JASPIAuthenticator` sets two ThreadLocal variables. Under specific conditions, the code prematurely returns without clearing these ThreadLocal variables. As a result, a subsequent request processed by the same thread inherits these ThreadLocal values from the previous request, leading to broken access control and privilege escalation. This vulnerability could allow an attacker to gain unauthorized access or elevated privileges within the Jetty application.

## Attack Chain

1. An unauthenticated user sends an initial request to the Jetty server.
2. The `JASPIAuthenticator` class initiates authentication checks for the request.
3. The `JASPIAuthenticator` sets ThreadLocal variables to store authentication-related data.
4. Due to specific conditions (e.g., an error or incomplete authentication), the `JASPIAuthenticator` returns early without clearing the ThreadLocal variables.
5. A subsequent request from a different user (or even the same user) is processed by the same thread.
6. The `JASPIAuthenticator` reuses the thread, inheriting the stale ThreadLocal values from the previous request.
7. The inherited ThreadLocal values bypass or alter the authentication checks, granting the subsequent request unauthorized access.
8. The attacker gains elevated privileges or access to sensitive data due to the broken access control.

## Impact

Successful exploitation of this vulnerability (CVE-2026-5795) results in broken access control and privilege escalation within the Eclipse Jetty server. An attacker could potentially gain unauthorized access to sensitive resources, perform actions on behalf of other users, or elevate their privileges to an administrative level. The exact impact depends on the specific configuration of the Jetty server and the resources it protects.

## Recommendation

*   Apply the patch or upgrade to a version of Eclipse Jetty that addresses CVE-2026-5795 to remediate the vulnerability.
*   Monitor web server logs for anomalies related to authentication, particularly around the `JASPIAuthenticator` class, to detect potential exploitation attempts.
*   Implement robust authentication and authorization mechanisms in your Jetty applications to minimize the impact of potential access control bypasses.
