---
title: Budibase Multiple Vulnerabilities Allow Privilege Escalation and Information Disclosure
slug: 2026-05-budibase-multiple-vulnerabilities
description: A remote, authenticated attacker can exploit multiple vulnerabilities in Budibase to gain administrator rights, bypass security measures, conduct cross-site scripting attacks, or disclose confidential information.
date: "2026-05-18T10:54:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - privilege-escalation
  - xss
  - budibase
vendors:
  - Budibase
products:
  - Budibase
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: JavaScript'
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1564
rules:
  - title: Detect Budibase Privilege Escalation Attempt
    description: Detects attempts to escalate privileges in Budibase by modifying user roles via API requests.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect Budibase XSS Attempt
    description: Detects attempts to inject malicious JavaScript code into Budibase web pages.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Multiple vulnerabilities in Budibase allow a remote, authenticated attacker to perform several malicious actions. These vulnerabilities, if successfully exploited, can lead to privilege escalation, allowing the attacker to gain administrator rights within the Budibase application. The attacker can also bypass existing security measures, potentially gaining unauthorized access to sensitive resources. Furthermore, the vulnerabilities enable Cross-Site Scripting (XSS) attacks, which can compromise user sessions and inject malicious scripts into the application's interface. Finally, sensitive information, such as user credentials or internal application data, could be disclosed to the attacker. This poses a significant risk to the confidentiality and integrity of data stored and processed within Budibase.

## Attack Chain

1. The attacker gains initial access to a Budibase instance with valid user credentials, potentially through credential stuffing or phishing.
2. The attacker identifies an endpoint vulnerable to privilege escalation, potentially related to insecure direct object references or improper permission checks (T1068).
3. The attacker crafts a malicious request to the identified endpoint to modify user roles, granting themselves administrator privileges.
4. With administrator privileges, the attacker accesses sensitive configuration settings or data within the Budibase application.
5. The attacker identifies a separate endpoint vulnerable to Cross-Site Scripting (XSS), potentially through improper input sanitization.
6. The attacker injects a malicious JavaScript payload into the vulnerable endpoint, which is executed when other users interact with the application (T1190).
7. The attacker uses the XSS payload to steal user session cookies or redirect users to a phishing site.
8. The attacker leverages their escalated privileges and stolen session cookies to access and exfiltrate sensitive information from the Budibase instance (T1555).

## Impact

Successful exploitation of these vulnerabilities can lead to a complete compromise of the Budibase application and the data it manages. Attackers could gain full control over the application, potentially impacting all users and applications built on the platform. Sensitive data, including user credentials, application data, and internal configuration information, could be exposed, leading to financial loss, reputational damage, and regulatory fines.

## Recommendation

*   Deploy the Sigma rule `Detect Budibase Privilege Escalation Attempt` to detect attempts to modify user roles through suspicious API requests. Enable webserver logging and tune the rule for your environment.
*   Deploy the Sigma rule `Detect Budibase XSS Attempt` to detect attempts to inject malicious JavaScript code into Budibase web pages. Ensure proper encoding of webserver logs to capture special characters.
*   Conduct a thorough security review of all Budibase applications to identify and remediate potential vulnerabilities.
