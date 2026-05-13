---
title: cPanel & WHM Multiple Vulnerabilities
slug: 2026-05-cpanel-vulns
description: cPanel released security advisories addressing vulnerabilities in cPanel & WebHost Manager (WHM) software versions prior to 11.86.0.44, 11.94.0.31, 11.102.0.42, 11.110.0.118, 11.118.0.67, 11.124.0.38, 11.126.0.59, 11.130.0.23, 11.132.0.32, 11.134.0.26, 11.136.0.10 and WP Squared 11.136.1.12.
date: "2026-05-13T18:41:54Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cpanel
  - vulnerability
  - webserver
vendors:
  - cPanel
products:
  - cPanel & WebHost Manager (WHM) software < 11.86.0.44
  - cPanel & WebHost Manager (WHM) software < 11.94.0.31
  - cPanel & WebHost Manager (WHM) software < 11.102.0.42
  - cPanel & WebHost Manager (WHM) software < 11.110.0.118
  - cPanel & WebHost Manager (WHM) software < 11.118.0.67
  - cPanel & WebHost Manager (WHM) software < 11.124.0.38
  - cPanel & WebHost Manager (WHM) software < 11.126.0.59
  - cPanel & WebHost Manager (WHM) software < 11.130.0.23
  - cPanel & WebHost Manager (WHM) software < 11.132.0.32
  - cPanel & WebHost Manager (WHM) software < 11.134.0.26
  - cPanel & WebHost Manager (WHM) software < 11.136.0.10
  - WP Squared 11.136.1.12
references:
  - https://cyber.gc.ca/en/alerts-advisories/cpanel-security-advisory-av26-464
  - https://support.cpanel.net/hc/en-us/sections/360007088193-Security
rules:
  - title: Detect Potential cPanel Brute Force Attacks
    description: Detects potential brute force attacks against cPanel login pages based on multiple failed login attempts from the same IP address.
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - webserver
  - title: Detect Access to cPanel Configuration Files
    description: Detects attempts to access sensitive cPanel configuration files, potentially indicating an information disclosure attempt.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1592.002
    data_sources:
      - webserver
  - title: Detecting requests to cPanel backups
    description: Detects access to potential backup files on the webserver.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - webserver
rules_count: 3
---

On May 13, 2026, cPanel published security advisories addressing multiple vulnerabilities affecting cPanel & WebHost Manager (WHM) software. These vulnerabilities impact versions prior to 11.86.0.44, 11.94.0.31, 11.102.0.42, 11.110.0.118, 11.118.0.67, 11.124.0.38, 11.126.0.59, 11.130.0.23, 11.132.0.32, 11.134.0.26, 11.136.0.10, and WP Squared 11.136.1.12. Successful exploitation of these vulnerabilities could lead to various impacts, including unauthorized access, information disclosure, or remote code execution, depending on the specific flaw. System administrators are urged to apply the necessary updates as soon as possible to mitigate potential risks. The specific nature of the vulnerabilities is not detailed in this advisory.

## Attack Chain

1.  Attacker identifies a vulnerable cPanel & WHM instance running an outdated version.
2.  Attacker leverages publicly available exploit code or develops a custom exploit based on disclosed vulnerability details.
3.  Attacker sends a malicious HTTP request to the targeted cPanel & WHM server, triggering the vulnerability.
4.  If successful, the attacker gains unauthorized access to the cPanel & WHM system.
5.  Attacker escalates privileges within the cPanel & WHM environment, potentially gaining root access.
6.  Attacker deploys a web shell or other persistent backdoor for continued access and control.
7.  Attacker uses the compromised system to launch further attacks, such as defacement, data exfiltration, or malware distribution.
8.  Attacker attempts to move laterally within the network, compromising other systems and resources.

## Impact

Successful exploitation of these vulnerabilities in cPanel & WHM could lead to significant consequences for web hosting providers and their customers. Impacts may include unauthorized access to sensitive data, defacement of websites, disruption of services, and potential financial losses. The number of affected systems is potentially large, given the widespread use of cPanel & WHM in the web hosting industry.

## Recommendation

*   Immediately upgrade cPanel & WebHost Manager (WHM) software to the latest versions (11.86.0.44, 11.94.0.31, 11.102.0.42, 11.110.0.118, 11.118.0.67, 11.124.0.38, 11.126.0.59, 11.130.0.23, 11.132.0.32, 11.134.0.26, 11.136.0.10 and WP Squared 11.136.1.12 or later) as recommended in the cPanel Security advisory.
*   Monitor web server logs for suspicious activity that may indicate exploitation attempts, focusing on unusual HTTP requests and error codes (webserver category).
*   Implement a web application firewall (WAF) with rulesets designed to detect and block common cPanel & WHM exploits (webserver category).
