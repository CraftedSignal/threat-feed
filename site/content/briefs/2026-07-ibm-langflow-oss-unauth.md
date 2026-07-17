---
title: IBM Langflow OSS Improper Authentication Vulnerability
slug: 2026-07-ibm-langflow-oss-unauth
description: A remote attacker can gain full administrative access to IBM Langflow OSS versions 1.0.0 through 1.10.0 by exploiting an improper authentication vulnerability. The /api/v1/login/auto_login endpoint, when the default AUTO_LOGIN configuration is enabled, issues long-lived superuser bearer tokens without requiring authentication. This allows an unauthenticated network attacker to obtain these tokens and achieve superuser privileges. Additionally, permissive Cross-Origin Resource Sharing (CORS) settings could expose these tokens to unintended origins, exacerbating the risk.
date: "2026-07-17T19:18:48Z"
lastmod: "2026-07-17T20:22:51Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - web-application
  - api-exploitation
  - improper-authentication
  - cve
  - privilege-escalation
  - code-injection
  - critical-vulnerability
  - ibm
vendors:
  - IBM
products:
  - Langflow OSS (1.0.0 through 1.10.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: IBM Langflow OSS 1.0.0 through 1.10.0 could allow a remote attacker to gain unauthorized access due to improper authentication in the /api/v1/login/auto_login endpoint.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The endpoint issues long-lived superuser bearer tokens without requiring authentication when the AUTO_LOGIN configuration is enabled (enabled by default), which may allow an unauthenticated network attacker to obtain full administrative access.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: allows an unauthenticated network attacker to obtain full administrative access.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: allows authenticated users to escalate privileges to superuser by directly manipulating the database
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: execute arbitrary system commands
    confidence_band: high
cves:
  - id: CVE-2026-9103
    cvss: 9.8
  - id: CVE-2026-8859
    cvss: 9.9
  - id: CVE-2026-8635
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9103
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8635
  - https://www.ibm.com/support/pages/node/7278925
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8859
rules:
  - title: Detects CVE-2026-9103 Exploitation - Unauthenticated Admin Token Request
    description: Detects CVE-2026-9103 exploitation by identifying unauthenticated POST requests to the /api/v1/login/auto_login endpoint in IBM Langflow OSS, which can lead to the issuance of superuser bearer tokens.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1190
      - T1552
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-07-17T20:22:31Z"
    level: L2
    summary: 'merged source coverage: IBM Langflow OSS Privilege Escalation via Database Manipulation (CVE-2026-8635)'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-8635
  - at: "2026-07-17T20:22:51Z"
    level: L2
    summary: added CVE-2026-8635 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-8859
---

IBM Langflow OSS versions 1.0.0 through 1.10.0 are affected by a critical improper authentication vulnerability, tracked as CVE-2026-9103. A remote unauthenticated attacker can exploit this flaw to gain full administrative access to affected instances. The vulnerability resides in the `/api/v1/login/auto_login` endpoint, which, when the `AUTO_LOGIN` configuration is enabled (a default setting), issues long-lived superuser bearer tokens without requiring any authentication. This allows an attacker to directly request and obtain a superuser token, bypassing intended security measures. Furthermore, permissive Cross-Origin Resource Sharing (CORS) settings present in the application could inadvertently expose these sensitive tokens to unintended origins, significantly increasing the risk of unauthorized access and potential compromise of the Langflow instance. The vulnerability has a CVSS v3.1 base score of 9.8, indicating its critical severity and ease of exploitation.

## Attack Chain

1. An unauthenticated remote attacker identifies a vulnerable IBM Langflow OSS instance running versions 1.0.0 through 1.10.0.
2. The attacker sends an HTTP POST request to the `/api/v1/login/auto_login` endpoint on the target Langflow instance.
3. Due to the `AUTO_LOGIN` configuration being enabled by default, the application processes this unauthenticated request.
4. The Langflow application responds to the attacker's request by issuing a long-lived superuser bearer token.
5. The attacker extracts this superuser bearer token from the HTTP response.
6. The attacker then uses the acquired superuser token in the Authorization header of subsequent API requests to impersonate an administrator.
7. With administrative privileges, the attacker can perform arbitrary actions within the Langflow instance, including modifying configurations, accessing sensitive data, or deploying malicious flows.

## Impact

Successful exploitation of CVE-2026-9103 grants a remote unauthenticated attacker full administrative access to the compromised IBM Langflow OSS instance. This allows for complete control over the application, enabling data exfiltration, modification of critical configurations, or the deployment of malicious AI flows. Given the nature of Langflow as a tool for creating AI applications, an attacker could potentially inject malicious logic into AI workflows, leading to broader system compromise or data manipulation. The permissive CORS settings further increase the risk by potentially allowing the exfiltration of these superuser tokens from user browsers via cross-site scripting (XSS) or other web-based attacks.

## Recommendation

* Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious administrative access attempts.
* Monitor webserver logs for unexpected POST requests to the `/api/v1/login/auto_login` endpoint, especially if not originating from trusted internal sources.
* Review the configuration of your IBM Langflow OSS instance immediately, and if possible, disable the `AUTO_LOGIN` setting if it is not strictly required for your operational needs.
* Patch CVE-2026-9103 by upgrading IBM Langflow OSS to a version greater than 1.10.0 as soon as a fix is available from the vendor.
