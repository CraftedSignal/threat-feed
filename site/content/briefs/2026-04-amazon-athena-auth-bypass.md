---
title: Amazon Athena ODBC Driver Authentication Bypass Vulnerability (CVE-2026-35561)
slug: 2026-04-amazon-athena-auth-bypass
description: CVE-2026-35561 describes an insufficient authentication security control vulnerability in the browser-based authentication components of the Amazon Athena ODBC driver before version 2.1.0.0, potentially allowing a threat actor to intercept or hijack authentication sessions.
date: "2026-04-03T21:17:12Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - amazon
  - athena
  - odbc
  - authentication
  - hijacking
  - cve-2026-35561
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1185
    technique_name: Drive-by Compromise
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-35561
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35561
  - https://aws.amazon.com/security/security-bulletins/2026-013-aws/
  - https://docs.aws.amazon.com/athena/latest/ug/odbc-v2-driver-release-notes.html
rules:
  - title: Detect Suspicious Athena ODBC Driver User Agent
    description: Detects connections using older, vulnerable Amazon Athena ODBC driver versions based on the User-Agent string.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Network Connection from Amazon Athena ODBC Driver
    description: Detects network connections from the Amazon Athena ODBC driver to unusual or unexpected destinations, potentially indicating compromised credentials or session hijacking.
    platform: sigma
    severity: low
    tactics:
      - lateral_movement
    techniques:
      - T1021.002
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-35561 identifies a critical vulnerability within the Amazon Athena ODBC driver, specifically affecting versions prior to 2.1.0.0. This flaw resides in the browser-based authentication components, where insufficient security controls could enable attackers to intercept or hijack legitimate authentication sessions. The vulnerability stems from inadequate protection mechanisms within the authentication flows, leaving users susceptible to unauthorized access. To mitigate this risk, Amazon recommends that users immediately upgrade to version 2.1.0.0 of the Athena ODBC driver. The affected driver is used on Windows, Linux, and macOS operating systems to connect to the Amazon Athena service. Successful exploitation could lead to unauthorized data access and manipulation within the victim's Athena environment.

## Attack Chain

1.  The attacker identifies a target using a vulnerable version of the Amazon Athena ODBC driver (prior to 2.1.0.0).
2.  The attacker intercepts the browser-based authentication flow initiated by the ODBC driver. This could involve techniques such as man-in-the-middle attacks or exploiting vulnerabilities in the underlying browser or network infrastructure.
3.  Due to insufficient security controls, the attacker is able to extract or manipulate the authentication credentials or session tokens.
4.  The attacker uses the stolen credentials to authenticate to Amazon Athena as the compromised user.
5.  The attacker queries sensitive data stored within Athena databases.
6.  The attacker modifies data within the Athena environment, potentially injecting malicious code or altering existing records.
7.  The attacker pivots to other AWS services accessible with the compromised account.

## Impact

Successful exploitation of CVE-2026-35561 can result in unauthorized access to sensitive data stored in Amazon Athena. The impact includes potential data breaches, data manipulation, and lateral movement to other AWS services if the compromised user has sufficient permissions. Given that Athena is often used to analyze large datasets, the compromise could expose significant amounts of business-critical information. The CVSS score of 7.4 highlights the severity of this vulnerability, particularly the high confidentiality and integrity impact.

## Recommendation

*   Immediately upgrade the Amazon Athena ODBC driver to version 2.1.0.0 or later across all affected systems to remediate CVE-2026-35561.
*   Monitor network traffic for suspicious authentication patterns related to Amazon Athena, using a network intrusion detection system (IDS) or firewall logs.
*   Implement multi-factor authentication (MFA) for all AWS accounts accessing Amazon Athena to mitigate the impact of compromised credentials.
*   Deploy the Sigma rule "Detect Suspicious Athena ODBC Driver User Agent" to identify potentially vulnerable or malicious driver versions in use.
*   Review and enforce least privilege access controls for all IAM roles and users accessing Amazon Athena to limit the potential impact of unauthorized access.
