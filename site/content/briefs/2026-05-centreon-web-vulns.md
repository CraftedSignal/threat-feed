---
title: Multiple Vulnerabilities in Centreon Web Allow RCE and Security Bypass
slug: 2026-05-centreon-web-vulns
description: Multiple vulnerabilities in Centreon Web versions 25.10.x before 25.10.12 and versions before 24.10.25 allow a remote attacker to achieve arbitrary code execution and bypass security policies.
date: "2026-05-29T14:40:26Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - centreon
  - rce
  - security-bypass
vendors:
  - Centreon
products:
  - Web versions 25.10.x
  - Web versions
affected_os:
  - linux
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0659/
  - https://thewatch.centreon.com/latest-security-bulletins-64/may-2026-monthly-security-bulletin-for-centreon-infra-monitoring-medium-5715
rules:
  - title: Detect Centreon Web Security Policy Bypass
    description: Detects potential security policy bypass attempts in Centreon Web via suspicious HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1203
    data_sources:
      - webserver
  - title: Detect Centreon Web Remote Code Execution Attempt
    description: Detects possible remote code execution attempts on Centreon Web servers by identifying suspicious POST requests with command injection patterns.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - webserver
rules_count: 2
---

Multiple vulnerabilities have been discovered in Centreon Web, a web-based interface for the Centreon IT infrastructure monitoring platform. The vulnerabilities affect Centreon Web versions 25.10.x prior to 25.10.12 and versions prior to 24.10.25. Successful exploitation of these vulnerabilities could allow an unauthenticated remote attacker to execute arbitrary code on the affected system and bypass security policies, potentially leading to complete system compromise. The CERT-FR published this advisory on May 29, 2026, following the release of Centreon's security bulletin on May 28, 2026. Organizations using affected versions of Centreon Web are advised to apply the necessary patches to mitigate the risks.

## Attack Chain

1.  Attacker identifies a vulnerable Centreon Web instance running a version prior to 25.10.12 or 24.10.25.
2.  Attacker crafts a malicious HTTP request to exploit a remote code execution vulnerability within the Centreon Web application.
3.  The malicious request is sent to the vulnerable Centreon Web server.
4.  The Centreon Web application processes the request without proper sanitization, leading to the execution of attacker-controlled code.
5.  The attacker's code executes with the privileges of the web server user.
6.  The attacker leverages the initial code execution to escalate privileges on the system.
7.  Attacker bypasses security policies, potentially gaining access to sensitive data or functionality.
8.  The attacker achieves arbitrary code execution, potentially installing malware, establishing persistence, or exfiltrating data.

## Impact

Successful exploitation of these vulnerabilities can allow a remote attacker to execute arbitrary code and bypass security policies. This could lead to complete compromise of the Centreon Web server, potentially affecting the entire monitoring infrastructure. The impact includes data breaches, system downtime, and further lateral movement within the network. Given Centreon's role in monitoring critical IT infrastructure, a successful attack could have significant consequences for affected organizations.

## Recommendation

*   Apply the security patches provided by Centreon as detailed in their security bulletin from May 28, 2026 to remediate the vulnerabilities in affected Centreon Web versions (versions 25.10.x before 25.10.12 and versions before 24.10.25).
*   Deploy the Sigma rule "Detect Centreon Web Security Policy Bypass" to identify potential security policy bypass attempts based on suspicious HTTP requests targeting the webserver.
*   Monitor webserver logs for suspicious activity, such as unusual HTTP requests or unexpected code execution, to identify potential exploitation attempts against Centreon Web.
