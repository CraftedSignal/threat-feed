---
title: IBM WebSphere Application Server Authentication Bypass Vulnerability (CVE-2026-16184)
slug: 2026-07-ibm-websphere-auth-bypass
description: A remote attacker can bypass authentication in IBM WebSphere Application Server versions 9.0 and 8.5 by sending a crafted unauthenticated request, potentially leading to unauthorized access and impact on confidentiality, integrity, and availability.
date: "2026-07-28T20:21:12Z"
lastmod: "2026-07-28T21:30:35Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - authentication-bypass
  - websphere
  - broken-access-control
  - privilege-escalation
  - deserialization
  - RCE
  - server-side-request-forgery
  - cwe-502
  - http-smuggling
  - server-side
  - http-request-smuggling
  - web-vulnerability
  - cve
vendors:
  - IBM
products:
  - WebSphere Application Server 9.0
  - WebSphere Application Server 8.5
  - WebSphere Application Server - Liberty >= 17.0.0.3 <= 26.0.0.7
  - WebSphere Application Server - Liberty 17.0.0.3
  - WebSphere Application Server - Liberty 26.0.0.7
  - WebSphere Application Server (9.0)
  - WebSphere Application Server (8.5)
  - WebSphere Application Server - Liberty (>= 17.0.0.3, <= 26.0.0.7)
  - WebSphere Application Server - Liberty
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: IBM WebSphere Application Server ... could allow a remote attacker to bypass authentication by sending a crafted unauthenticated request.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: IBM WebSphere Application Server 9.0, and 8.5 is vulnerable to broken access control/privilege escalation in the administrative console.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: unsafe deserialization which could allow a remote attacker to [...] execute arbitrary code.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: HTTP request smuggling allows attackers to bypass security controls.
    confidence_band: med
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: Exploitation could lead to web cache poisoning.
    confidence_band: med
cves:
  - id: CVE-2026-16184
    cvss: 7
  - id: CVE-2026-14528
    cvss: 7.4
  - id: CVE-2026-14446
    cvss: 9.8
  - id: CVE-2026-14512
    cvss: 9.8
  - id: CVE-2026-14981
    cvss: 7.5
  - id: CVE-2026-15325
    cvss: 8.7
  - id: CVE-2026-15064
    cvss: 8.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16184
  - https://www.ibm.com/support/pages/node/7281628
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14446
  - https://www.ibm.com/support/pages/node/7281631
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14512
  - https://www.ibm.com/support/pages/node/7281649
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14528
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14981
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15064
  - https://www.ibm.com/support/pages/node/7281625
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15325
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15328
iocs:
  - type: domain
    value: nvd.nist.gov
  - type: url
    value: https://nvd.nist.gov
  - type: url
    value: https://www.ibm.com/support/pages/node/7281649
  - type: email
    value: nvd@nist.gov
  - type: email
    value: soc@us-cert.gov
ioc_counts:
  domain: 1
  email: 2
  url: 2
updates:
  - at: "2026-07-28T21:24:21Z"
    level: L2
    summary: added CVE-2026-14446 +2
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-14528
  - at: "2026-07-28T21:26:25Z"
    level: L2
    summary: added CVE-2026-14981
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-14981
  - at: "2026-07-28T21:28:32Z"
    level: L2
    summary: 'merged source coverage: IBM WebSphere Application Server Vulnerable to HTTP Response Smuggling (CVE-2026-15064)'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-15064
  - at: "2026-07-28T21:29:35Z"
    level: L2
    summary: added CVE-2026-15064 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-15325
  - at: "2026-07-28T21:30:35Z"
    level: L2
    summary: 'merged source coverage: IBM WebSphere Application Server HTTP Request Smuggling Vulnerability'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-15328
---

IBM has identified a high-severity vulnerability, CVE-2026-16184, affecting its WebSphere Application Server versions 9.0 and 8.5. This flaw, categorized as a Missing Authorization (CWE-862), allows a remote, unauthenticated attacker to bypass the server's authentication mechanisms. By sending a specially crafted request, an attacker can gain unauthorized access to the application server. This vulnerability can lead to unauthorized information disclosure, data modification, or denial of service, depending on the accessed resources and the attacker's capabilities post-bypass. Organizations using affected WebSphere versions are advised to apply the necessary patches provided by IBM to mitigate the risk of exploitation.

## Attack Chain

1. A remote, unauthenticated attacker identifies a public-facing IBM WebSphere Application Server instance running a vulnerable version (9.0 or 8.5).
2. The attacker performs initial reconnaissance to understand the server's exposed endpoints and the expected authentication process.
3. The attacker crafts a specific HTTP request designed to exploit the missing authorization vulnerability (CWE-862) within the WebSphere server's authentication logic.
4. This crafted request is intentionally formed to bypass standard authentication checks, possibly by manipulating specific HTTP headers, cookies, URL parameters, or the request body content.
5. The attacker sends this unauthenticated, crafted request to the vulnerable WebSphere Application Server.
6. The server processes the request, and due to the underlying vulnerability, it fails to properly enforce authentication requirements, allowing the request to proceed as if authenticated.
7. Consequently, the attacker gains unauthorized access to resources, functionalities, or administrative interfaces within the application server without providing valid credentials.
8. With unauthorized access, the attacker can potentially perform actions such as information disclosure, unauthorized data modification, or disrupt the availability of the server.

## Impact

Successful exploitation of CVE-2026-16184 could lead to a significant compromise of the affected IBM WebSphere Application Server instance. Attackers could gain unauthorized access to sensitive data, modify application configurations, or disrupt critical services, leading to a loss of confidentiality, integrity, and availability for applications hosted on the server. While specific victim counts or sectors are not detailed, any organization running unpatched versions of WebSphere Application Server 9.0 or 8.5, particularly those exposed to the internet, is at risk.

## Recommendation

* Patch CVE-2026-16184 on all IBM WebSphere Application Server 9.0 and 8.5 instances immediately by applying the updates referenced in the IBM Corporation advisory `https://www.ibm.com/support/pages/node/7281628`.
* Monitor `webserver` logs for suspicious unauthenticated requests, specifically looking for abnormal access patterns to sensitive endpoints.
* Implement strong network segmentation and access controls to limit exposure of IBM WebSphere Application Server instances to untrusted networks.
