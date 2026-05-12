---
title: cPanel & WHM Multiple Vulnerabilities Leading to Privilege Escalation
slug: 2026-05-cpanel-privesc
description: Multiple vulnerabilities in cPanel & WHM and WP Squared allow authenticated users to escalate privileges, execute arbitrary code, and cause denial-of-service conditions by exploiting improper input validation and unsafe symlink handling.
date: "2026-05-12T08:23:54Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cpanel
  - privilege-escalation
  - code-execution
vendors:
  - cPanel
products:
  - cPanel & WHM
  - WP Squared
affected_os:
  - linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
cves:
  - id: CVE-2026-29201
    cvss: 4.3
    epss: 0.0004
  - id: CVE-2026-29202
    cvss: 8.8
    epss: 0.00095
  - id: CVE-2026-29203
    cvss: 8.8
    epss: 0.00042
references:
  - https://ccb.belgium.be/advisories/warning-multiple-vulnerabilities-cpanel-and-whm-leading-privilege-escalation-patch
  - https://support.cpanel.net/hc/en-us/articles/40311033698327-Security-CVE-2026-29201-cPanel-WHM-WP2-Security-Update-May-08-2026
  - https://support.cpanel.net/hc/en-us/articles/40311426610327-Security-CVE-2026-29202-cPanel-WHM-WP2-Security-Update-May-08-2026
  - https://support.cpanel.net/hc/en-us/articles/40311543760407-Security-CVE-2026-29203-cPanel-WHM-WP2-Security-Update-May-08-2026
  - https://nvd.nist.gov/vuln/detail/CVE-2026-29201
  - https://nvd.nist.gov/vuln/detail/CVE-2026-29202
  - https://nvd.nist.gov/vuln/detail/CVE-2026-29203
rules:
  - title: Detect cPanel create_user API Abuse
    description: Detects CVE-2026-29201 exploitation — identifies suspicious cPanel create_user API calls with potentially malicious Perl code in the plugin parameter, indicating a possible code injection attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - webserver
  - title: Detect CVE-2026-29202 - Suspicious Chmod Usage
    description: Detects CVE-2026-29202 exploitation — Identifies attempts to modify file permissions (chmod) on system files which may lead to privilege escalation or denial of service.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect CVE-2026-29203 - Arbitrary File Read via adminbin
    description: Detects CVE-2026-29203 exploitation — Detects access to sensitive files by abusing the LOADFEATUREFILE functionality in adminbin.
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

Multiple vulnerabilities have been identified in cPanel & WHM versions 11.136.0.8 and lower, 11.134.0.24 and lower, 11.132.0.30 and lower, 11.130.0.21 and lower, 11.126.0.57 and lower, 11.124.0.36 and lower, 11.118.0.65 and lower, 11.110.0.115 and lower, 11.110.0.116 and lower, 11.102.0.40 and lower, 11.94.0.29 and lower, 11.86.0.42 and lower, and WP Squared version 11.136.1.9 and higher. These vulnerabilities include a Perl code injection flaw in the `create_user` API call (CVE-2026-29201), an unsafe symlink handling error that allows arbitrary file modification (CVE-2026-29202), and an arbitrary file read vulnerability in the `feature::LOADFEATUREFILE` adminbin call (CVE-2026-29203). Successful exploitation of these vulnerabilities can lead to privilege escalation, arbitrary code execution, and denial-of-service conditions.

## Attack Chain

1. An authenticated user logs into cPanel & WHM.
2. The user crafts a malicious `create_user` API call, injecting Perl code into the `plugin` parameter (CVE-2026-29201).
3. The crafted API call is sent to the cPanel & WHM server.
4. The server executes the injected Perl code on behalf of the authenticated user's system account.
5. Alternatively, the user exploits the unsafe symlink handling error (CVE-2026-29202) to manipulate file permissions using chmod on arbitrary files via a crafted request.
6. A user exploits the `feature::LOADFEATUREFILE` adminbin call (CVE-2026-29203) by providing a relative path, causing an arbitrary file to become world-readable.
7. An attacker leverages the ability to read arbitrary files to gain sensitive information.
8. The attacker uses the escalated privileges or sensitive information to further compromise the system.

## Impact

Successful exploitation of these vulnerabilities can lead to significant impact. An attacker can execute arbitrary code with the privileges of the cPanel user, potentially compromising the entire hosting environment. The unsafe symlink handling error can lead to denial of service by modifying critical system files or privilege escalation. The arbitrary file read vulnerability can expose sensitive information, such as configuration files or credentials. The CCB warns of a high impact on confidentiality, integrity, and availability.

## Recommendation

*   Immediately patch cPanel & WHM and WP Squared to the latest versions to remediate CVE-2026-29201, CVE-2026-29202, and CVE-2026-29203.
*   Monitor cPanel & WHM logs for suspicious API calls to `create_user` with unusual `plugin` parameters to detect potential CVE-2026-29201 exploitation.
*   Implement the Sigma rule "Detect cPanel create_user API Abuse" to identify potential attempts to inject Perl code via the `create_user` API call.
*   Monitor file permission changes, especially involving chmod, for unusual activity that may indicate exploitation of CVE-2026-29202.
