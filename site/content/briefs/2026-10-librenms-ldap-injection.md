---
title: LDAP Filter Injection in LibreNMS Authentication Modules
slug: 2026-10-librenms-ldap-injection
description: LibreNMS versions prior to 26.9.0 are vulnerable to LDAP filter injection, allowing unauthenticated attackers to bypass authentication and gain administrative access via crafted HTTP Basic Authorization headers.
date: "2026-10-12T18:37:49Z"
lastmod: "2026-10-12T20:30:11Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:librenms:librenms:*:*:*:*:*:*:*:*
tags:
  - ldap-injection
  - authentication-bypass
  - web-vulnerability
vendors:
  - LibreNMS
products:
  - LibreNMS (< 26.9.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can supply a crafted wildcard username through the HTTP Basic Authorization header to bypass authentication and gain administrative access to the LibreNMS instance.
    confidence_band: high
cves:
  - id: CVE-2026-109357
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109357
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109353
rules:
  - title: Detect CVE-2026-109357 Exploitation - LDAP Filter Injection Attempt
    description: Detects exploitation attempts against CVE-2026-109357 by monitoring for HTTP requests containing common LDAP wildcard or injection characters in the PHP_AUTH_USER field.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-109353 - SQL Injection Attempt in LibreNMS
    description: Detects potential exploitation attempts of CVE-2026-109353 where an array is passed to the notification_id parameter in notifications.inc.php
    platform: sigma
    severity: high
    tactics:
      - exfiltration
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade LibreNMS to version 26.9.0 or later.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-109357 patch requirement.
  hunt_leads:
    - lead: Search web logs for requests containing wildcard characters in the username field.
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: LDAP filter injection technique.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 26.9.0.
      owner: IT Operations
      addresses: CVE-2026-109357
      evidence: NVD vulnerability notice.
updates:
  - at: "2026-10-12T20:30:11Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-109353 - SQL Injection Attempt in LibreNMS'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-109353
---

LibreNMS versions before 26.9.0 contain a critical vulnerability in the ldap-authorization and ad-authorization modules. The application fails to properly sanitize and escape usernames before incorporating them into LDAP search filters during the authentication process. Because the authentication logic only verifies the existence of a user rather than validating their credentials, the application is susceptible to LDAP filter injection. An unauthenticated attacker can exploit this by submitting a crafted username, such as a wildcard character, within the PHP_AUTH_USER field of an HTTP Basic Authorization header. This manipulation causes the LDAP backend to return a successful match for all users and groups, effectively bypassing authentication controls and granting the attacker administrative privileges within the LibreNMS instance.

## Attack Chain

1. Attacker identifies an internet-facing LibreNMS instance using ldap-authorization or ad-authorization.
2. Attacker crafts an HTTP request containing the HTTP Basic Authorization header.
3. Attacker populates the PHP_AUTH_USER parameter with an LDAP injection payload (e.g., a wildcard character '*').
4. The LibreNMS server receives the request and parses the unescaped username for the LDAP search filter.
5. The application executes the malformed LDAP query against the configured directory server.
6. The directory server returns a positive match for the injected query, signaling user existence to the LibreNMS application.
7. LibreNMS grants the attacker an active session based on the successful, albeit bypassed, authentication check.
8. Attacker gains full administrative access to the network monitoring dashboard, enabling exfiltration of network topology data or further system exploitation.

## Impact

Successful exploitation allows an unauthenticated, remote attacker to bypass authentication mechanisms and gain administrative control over the LibreNMS monitoring platform. This access provides visibility into sensitive network infrastructure, including device configurations, performance metrics, and network maps. Depending on the environment, an attacker could leverage this platform access to pivot into the internal network, modify monitoring alerts to conceal malicious activity, or gain further credentials stored within the monitoring system.

## Recommendation

* Upgrade LibreNMS to version 26.9.0 or later immediately to patch the improper input validation in authentication modules.
* Monitor web server logs for HTTP requests with unusual characters or wildcard patterns in the PHP_AUTH_USER field to detect exploitation attempts.
* If upgrading is not immediately possible, restrict access to the LibreNMS web interface to trusted internal networks or implement additional pre-authentication controls (e.g., VPN or mTLS) to mitigate unauthenticated access.
* Audit web server access logs for anomalous, high-frequency authentication attempts originating from a single source or utilizing non-standard usernames.
