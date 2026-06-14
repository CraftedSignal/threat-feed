---
title: Multiple Vulnerabilities in Typo3 Leading to RCE, Privilege Escalation, and Data Compromise
slug: 2026-06-typo3-multi-vuln
description: Multiple vulnerabilities discovered in Typo3 allow an attacker to achieve remote arbitrary code execution, privilege escalation, data confidentiality compromise, data integrity compromise, security policy bypass, remote indirect code injection (XSS), and SQL injection (SQLi).
date: "2026-06-14T09:18:23Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - web-vulnerability
  - rce
  - privilege-escalation
  - data-exfiltration
  - typo3
  - cert-fr
vendors:
  - Typo3
products:
  - Typo3 < 10.4.57
  - Typo3 < 11.5.51
  - Typo3 < 12.4.46
  - Typo3 < 13.4.31
  - Typo3 < 14.3.3
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
cves:
  - id: CVE-2026-47348
    epss: 0.00044
  - id: CVE-2026-47349
    epss: 0.00036
  - id: CVE-2026-47350
    epss: 0.0003
  - id: CVE-2026-47351
    epss: 0.00036
  - id: CVE-2026-47352
    epss: 0.00036
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0722/
  - https://github.com/TYPO3/typo3/security/advisories/GHSA-2j54-93q2-3hjq
  - https://github.com/TYPO3/typo3/security/advisories/GHSA-c78m-c52x-jgwp
  - https://github.com/TYPO3/typo3/security/advisories/GHSA-cg75-qfg2-w9hj
  - https://github.com/TYPO3/typo3/security/advisories/GHSA-chm7-4vch-h8vr
  - https://github.com/TYPO3/typo3/security/advisories/GHSA-f34x-rx2w-7pm3
  - https://github.com/TYPO3/typo3/security/advisories/GHSA-jf56-v8jc-jcc5
  - https://github.com/TYPO3/typo3/security/advisories/GHSA-jh32-v29g-68pq
  - https://github.com/TYPO3/typo3/security/advisories/GHSA-pjpj-v387-x4vq
  - https://github.com/TYPO3/typo3/security/advisories/GHSA-q93m-25xv-94hh
  - https://github.com/TYPO3/typo3/security/advisories/GHSA-qcmw-6rm2-5x78
  - https://www.cve.org/CVERecord?id=CVE-2026-11607
  - https://www.cve.org/CVERecord?id=CVE-2026-47348
  - https://www.cve.org/CVERecord?id=CVE-2026-47349
  - https://www.cve.org/CVERecord?id=CVE-2026-47350
  - https://www.cve.org/CVERecord?id=CVE-2026-47351
  - https://www.cve.org/CVERecord?id=CVE-2026-47352
  - https://www.cve.org/CVERecord?id=CVE-2026-49738
  - https://www.cve.org/CVERecord?id=CVE-2026-49740
  - https://www.cve.org/CVERecord?id=CVE-2026-49741
  - https://www.cve.org/CVERecord?id=CVE-2026-49742
iocs:
  - type: url
    value: https://github.com/TYPO3/typo3/security/advisories/GHSA-2j54-93q2-3hjq
  - type: url
    value: https://github.com/TYPO3/typo3/security/advisories/GHSA-c78m-c52x-jgwp
  - type: url
    value: https://github.com/TYPO3/typo3/security/advisories/GHSA-cg75-qfg2-w9hj
  - type: url
    value: https://github.com/TYPO3/typo3/security/advisories/GHSA-chm7-4vch-h8vr
  - type: url
    value: https://github.com/TYPO3/typo3/security/advisories/GHSA-f34x-rx2w-7pm3
  - type: url
    value: https://github.com/TYPO3/typo3/security/advisories/GHSA-jf56-v8jc-jcc5
  - type: url
    value: https://github.com/TYPO3/typo3/security/advisories/GHSA-jh32-v29g-68pq
  - type: url
    value: https://github.com/TYPO3/typo3/security/advisories/GHSA-pjpj-v387-x4vq
  - type: url
    value: https://github.com/TYPO3/typo3/security/advisories/GHSA-q93m-25xv-94hh
  - type: url
    value: https://github.com/TYPO3/typo3/security/advisories/GHSA-qcmw-6rm2-5x78
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-11607
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-47348
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-47349
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-47350
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-47351
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-47352
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-49738
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-49740
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-49741
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-49742
ioc_counts:
  url: 20
rules:
  - title: Detects CVE-2026-11607 Exploitation Attempt - Typo3 RCE via Web Request
    description: Detects attempts to exploit Typo3 vulnerabilities like CVE-2026-11607 that allow remote code execution by looking for common command injection patterns in HTTP request URIs.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059
      - T1190
    data_sources:
      - webserver
  - title: Detects Typo3 SQL Injection Attempt - Web Server Logs
    description: Detects attempts to exploit SQL injection vulnerabilities in Typo3 by looking for common SQL keywords and patterns in HTTP request URIs, potentially related to CVE-2026-47349.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
      - T1588
    data_sources:
      - webserver
  - title: Detects Typo3 Cross-Site Scripting (XSS) Attempt
    description: Detects attempts to exploit Cross-Site Scripting (XSS) vulnerabilities in Typo3 by looking for common HTML script tags or event handlers in HTTP request URIs, potentially related to CVE-2026-47350.
    platform: sigma
    severity: medium
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
      - T1588
    data_sources:
      - webserver
rules_count: 3
---

CERT-FR has issued an advisory detailing multiple critical vulnerabilities within the Typo3 content management system (CMS), affecting versions 10.4.x (prior to 10.4.57), 11.x (prior to 11.5.51), 12.x (prior to 12.4.46), 13.x (prior to 13.4.31), and 14.x (prior to 14.3.3). These vulnerabilities, identified on June 9-10, 2026, collectively enable remote arbitrary code execution (RCE), privilege escalation, and significant data confidentiality breaches. Other risks include data integrity compromise, security policy bypass, remote indirect code injection (XSS), and SQL injection (SQLi). Attackers can leverage these flaws by sending specially crafted web requests to unpatched Typo3 instances, allowing them to gain control over the web server, access sensitive information, or escalate their privileges. This poses a severe risk to organizations running vulnerable Typo3 deployments, as successful exploitation could lead to full system compromise and significant operational disruption. While the advisory does not mention active exploitation, the severity of the vulnerabilities warrants immediate attention.

## Attack Chain

1. An attacker identifies an internet-facing Typo3 instance running a vulnerable version (e.g., Typo3 12.3.0) through reconnaissance or automated scanning.
2. The attacker crafts and sends a malicious HTTP request targeting a vulnerability such as CVE-2026-11607, attempting to achieve remote arbitrary code execution on the Typo3 server.
3. Upon successful exploitation, the malicious request triggers the execution of an arbitrary command (e.g., a reverse shell, `whoami`, `id`) on the underlying web server process.
4. The attacker leverages other vulnerabilities (e.g., CVE-2026-47348 for privilege escalation) or misconfigurations to elevate privileges from the web server user to a higher-privileged user on the host system.
5. The attacker establishes persistent access by installing a web shell, creating new user accounts, or modifying system startup configurations to maintain control.
6. With elevated privileges, the attacker accesses sensitive data stored on the server (e.g., database credentials, user information) and initiates its exfiltration.
7. The attacker might deface the website, deploy additional malware, or use the compromised server as a pivot point for further attacks within the network, causing significant operational damage.

## Impact

Successful exploitation of these Typo3 vulnerabilities can lead to severe consequences for affected organizations. Attackers gaining remote code execution can fully compromise the underlying web server, leading to data breaches involving sensitive customer or corporate information, potentially causing financial losses, regulatory fines, and reputational damage. Privilege escalation allows attackers to gain administrative control over the server, facilitating further network infiltration, deployment of ransomware, or establishment of long-term persistence. SQL injection and XSS vulnerabilities can lead to database compromise, theft of user session cookies, or delivery of client-side malware to visitors of the compromised website. While specific victim counts are not available, organizations across all sectors utilizing Typo3 are at risk.

## Recommendation

* Apply patches provided by Typo3 for all affected versions (Typo3 < 11.5.51, Typo3 < 12.4.46, Typo3 < 13.4.31, Typo3 < 14.3.3, Typo3 < 10.4.57) immediately.
* Deploy the Sigma rules provided in this brief, such as 'Detects CVE-2026-11607 Exploitation Attempt - Typo3 RCE via Web Request', to your webserver log monitoring solution to detect exploitation attempts.
* Implement web application firewalls (WAFs) or intrusion prevention systems (IPS) to block known attack patterns for RCE, SQLi, and XSS as described in the vulnerabilities like CVE-2026-11607, CVE-2026-47348, CVE-2026-47349, and CVE-2026-47350.
* Regularly review web server access logs for anomalous requests, particularly those containing command injection payloads or SQLi/XSS indicators (refer to 'Detects Typo3 SQL Injection Attempt' and 'Detects Typo3 Cross-Site Scripting (XSS) Attempt' rules).
