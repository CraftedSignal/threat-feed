---
title: cPanel and WHM Authentication Bypass Vulnerability (CVE-2026-41940)
slug: 2026-04-cpanel-auth-bypass
description: An authentication bypass vulnerability in cPanel and WHM versions prior to 11.110.0.97, 11.118.0.63, 11.126.0.54, 11.132.0.29, 11.134.0.20, and 11.136.0.5 allows unauthenticated remote attackers to gain unauthorized access to the control panel.
date: "2026-04-29T16:16:25Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - cpanel
  - whm
  - authentication-bypass
  - CVE-2026-41940
  - webserver
vendors:
  - cPanel
products:
  - WHM
  - cPanel
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-41940
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41940
  - https://docs.cpanel.net/release-notes/release-notes
  - https://docs.wpsquared.com/changelogs/versions/changelog/#13617
  - https://support.cpanel.net/hc/en-us/articles/40073787579671-cPanel-WHM-Security-Update-04-28-2026
  - https://www.namecheap.com/status-updates/ongoing-critical-security-vulnerability-in-cpanel-april-28-2026
  - https://www.vulncheck.com/advisories/cpanel-and-whm-authentication-bypass-via-login-flow
rules:
  - title: Detect Cpanel Authentication Bypass Access
    description: Detects potential exploitation attempts of the cPanel authentication bypass vulnerability (CVE-2026-41940) by monitoring access to the login page with unusual parameters or methods.
    platform: sigma
    severity: critical
    tactics:
      - cve-2026-41940
      - initial_access
    techniques:
      - T1190
      - T1586
    data_sources:
      - webserver
      - linux
  - title: Detect Cpanel Account Manipulation
    description: Detects creation, modification, or deletion of user accounts within cPanel, which may indicate post-exploitation activity.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - webserver
      - linux
rules_count: 2
---

On April 28, 2026, a critical authentication bypass vulnerability (CVE-2026-41940) was disclosed affecting cPanel and WHM. This vulnerability impacts versions prior to 11.110.0.97, 11.118.0.63, 11.126.0.54, 11.132.0.29, 11.134.0.20, and 11.136.0.5. The vulnerability exists within the login flow, allowing unauthenticated remote attackers to bypass authentication and gain unauthorized access to the control panel. Successful exploitation grants attackers complete control over the affected cPanel and WHM instances, potentially leading to data theft, server compromise, and further malicious activities. This vulnerability poses a significant risk to web hosting providers and their customers.

## Attack Chain

1.  An unauthenticated attacker sends a crafted HTTP request to the cPanel/WHM login page, exploiting the authentication bypass vulnerability.
2.  The vulnerable cPanel/WHM version fails to properly validate the request, allowing the attacker to bypass the login process.
3.  The attacker gains unauthorized access to the cPanel/WHM interface.
4.  The attacker enumerates the server to identify valuable files, directories, and database configurations.
5.  The attacker leverages the compromised cPanel/WHM access to upload malicious scripts or binaries.
6.  The attacker executes uploaded payloads to establish persistent access, such as a web shell.
7.  The attacker uses the web shell to perform arbitrary commands on the server, including escalating privileges.
8.  The attacker exfiltrates sensitive data, defaces websites, or deploys ransomware.

## Impact

Successful exploitation of CVE-2026-41940 can lead to complete compromise of cPanel and WHM servers. This can result in data breaches, website defacement, and denial-of-service attacks. The vulnerability affects a wide range of cPanel and WHM installations, potentially impacting thousands of web hosting providers and their customers. The high CVSS score (9.8) reflects the severity of the risk and the ease with which it can be exploited.

## Recommendation

*   Immediately upgrade cPanel and WHM installations to versions 11.110.0.97, 11.118.0.63, 11.126.0.54, 11.132.0.29, 11.134.0.20, or 11.136.0.5, or later to patch CVE-2026-41940.
*   Monitor web server logs for unusual activity and unauthorized access attempts to the cPanel/WHM interface by deploying the Sigma rule `DetectCpanelAuthBypassAccess`.
*   Implement strict access control policies to limit access to cPanel/WHM administrative interfaces and monitor the user activity by deploying the Sigma rule `DetectCpanelAccountManipulation`.
