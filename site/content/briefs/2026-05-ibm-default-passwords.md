---
title: IBM Operations Analytics and SmartCloud Analytics Default Password Vulnerability (CVE-2026-7365)
slug: 2026-05-ibm-default-passwords
description: IBM Operations Analytics - Log Analysis and IBM SmartCloud Analytics - Log Analysis use default passwords from the manufacturing process, potentially allowing attackers to bypass authentication.
date: "2026-05-27T14:20:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - default-password
  - authentication-bypass
vendors:
  - IBM
products:
  - Operations Analytics - Log Analysis
  - SmartCloud Analytics - Log Analysis
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
cves:
  - id: CVE-2026-7365
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7365
  - https://www.ibm.com/support/pages/node/7272268
rules:
  - title: Detect Default Password Login Attempt
    description: Detects login attempts using known default usernames for IBM Operations Analytics and SmartCloud Analytics.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - webserver
  - title: Detect CVE-2026-7365 Exploitation - Default Password Authentication
    description: Detects CVE-2026-7365 exploitation — successful authentication using default credentials for IBM Operations Analytics and IBM SmartCloud Analytics.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - webserver
rules_count: 2
---

IBM Operations Analytics - Log Analysis and IBM SmartCloud Analytics - Log Analysis are vulnerable to authentication bypass due to the use of default passwords during the installation process, as identified by CVE-2026-7365. These default passwords, intended for initial setup, are present from the manufacturing process and may be exposed or remain unchanged, posing a significant security risk. An attacker exploiting this vulnerability could gain unauthorized access to the system. This issue was reported on May 27, 2026, and affects installations that have not changed the default credentials. This vulnerability allows attackers to potentially gain complete control over the affected systems.

## Attack Chain

1.  The attacker identifies an IBM Operations Analytics or IBM SmartCloud Analytics instance.
2.  The attacker attempts to log in using known default credentials for the application.
3.  Upon successful authentication with default credentials, the attacker gains unauthorized access to the system.
4.  The attacker escalates privileges within the application to gain administrative control.
5.  The attacker configures the application to allow for remote access or installs a backdoor.
6.  The attacker uses the compromised system to gather sensitive data.
7.  The attacker modifies or deletes logs to cover their tracks.

## Impact

Successful exploitation of CVE-2026-7365 can lead to complete compromise of IBM Operations Analytics - Log Analysis and IBM SmartCloud Analytics - Log Analysis instances. This could result in unauthorized access to sensitive log data, configuration information, and the ability to manipulate the application's behavior. Given the nature of these systems, attackers could potentially gain access to a wide range of sensitive information logged by the applications and pivot to other systems.

## Recommendation

*   Immediately change the default passwords on all IBM Operations Analytics - Log Analysis and IBM SmartCloud Analytics - Log Analysis installations to mitigate CVE-2026-7365.
*   Deploy the Sigma rule "Detect Default Password Login Attempt" to monitor for login attempts using default credentials.
*   Monitor logs for suspicious activity following any successful login, as a default password login would be unusual in a hardened environment.
