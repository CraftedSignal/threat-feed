---
title: Langflow Multiple Vulnerabilities Allow Information Disclosure, Data Manipulation, and XSS
slug: 2026-03-langflow-vulns
description: An anonymous or authenticated remote attacker can exploit multiple vulnerabilities in Langflow to disclose information, manipulate data, and execute cross-site scripting attacks.
date: "2026-03-30T11:08:56Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - langflow
  - vulnerability
  - xss
  - data-manipulation
  - information-disclosure
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0900
rules:
  - title: Detect HTTP Data Manipulation Methods
    description: Detects potential data manipulation attempts by looking for unusual HTTP request methods like PUT, PATCH, or DELETE against Langflow web server
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect XSS attempts via Script Tags
    description: Detects possible XSS attacks through the use of `<script>` tags in HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Langflow is vulnerable to multiple security flaws that could be exploited by remote attackers. These vulnerabilities range from information disclosure to data manipulation and cross-site scripting (XSS). The vulnerabilities can be exploited by both anonymous and authenticated attackers, increasing the potential attack surface. Successful exploitation could lead to unauthorized access to sensitive information, modification of data, and execution of malicious scripts within the context of the affected application. These vulnerabilities pose a significant risk to organizations using Langflow, potentially leading to data breaches, service disruption, or further compromise of internal systems. Defenders need to implement measures to detect and prevent exploitation of these vulnerabilities.

## Attack Chain

1.  An attacker identifies a Langflow instance accessible over the network, either anonymously or with valid credentials.
2.  The attacker sends a crafted HTTP request to exploit an information disclosure vulnerability, potentially revealing sensitive data or configuration details.
3.  The attacker leverages revealed information to craft further attacks or identify additional vulnerabilities.
4.  The attacker exploits a data manipulation vulnerability, possibly through API endpoints, to modify application data, settings, or user accounts.
5.  The attacker injects malicious JavaScript code into Langflow through a cross-site scripting (XSS) vulnerability, potentially targeting other users or administrators.
6.  A legitimate user accesses the compromised Langflow instance, triggering the injected XSS payload in their browser.
7.  The XSS payload steals the user's session cookie or credentials, granting the attacker unauthorized access to their account.
8.  The attacker uses the compromised account to further escalate privileges or access sensitive resources within Langflow or connected systems.

## Impact

Successful exploitation of these vulnerabilities could result in significant damage. Information disclosure can expose sensitive data, undermining confidentiality. Data manipulation can lead to data corruption, denial of service, or unauthorized modifications to application functionality. XSS attacks can compromise user accounts, leading to further privilege escalation and access to sensitive resources. The number of affected users and the scope of the impact depend on the specific configuration and deployment of Langflow within the organization.

## Recommendation

*   Monitor web server logs for suspicious HTTP requests targeting Langflow (cs-uri-query, cs-uri-stem log fields).
*   Implement the provided Sigma rule to detect potential data manipulation attempts via unusual HTTP request methods.
*   Deploy the Sigma rule to detect potential XSS attacks using `Script` tag injections in HTTP requests.
*   Continuously monitor for unexpected modifications to Langflow application data or user accounts.
