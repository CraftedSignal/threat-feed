---
title: Multiple Vulnerabilities Discovered in SAP Products Including SQLi, XSS, and Policy Bypass
slug: 2026-06-sap-multiple-vulnerabilities
description: Multiple high-severity vulnerabilities discovered in various SAP products, including SQL injection (SQLi), remote indirect code injection (XSS), and security policy bypasses, could allow unauthenticated attackers to compromise sensitive enterprise systems by June 2026.
date: "2026-06-14T09:06:46Z"
lastmod: "2026-07-11T09:01:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sap
  - vulnerability
  - sqli
  - xss
  - web-application
vendors:
  - SAP
  - Apache
products:
  - Business Objects Business Intelligence Platform (ENTERPRISE 430)
  - Business Objects Business Intelligence Platform (2025)
  - Business Objects Business Intelligence Platform (2027)
  - Business Objects (ENTERPRISE 430)
  - Business Objects (2025)
  - Business Objects (2027)
  - Commerce Cloud and Data Hub (HY_COM 2205)
  - Commerce Cloud and Data Hub (HY_DHUB 2205)
  - Commerce Cloud and Data Hub (COM_CLOUD 2211)
  - Commerce Cloud and Data Hub (2211-JDK21)
  - Commerce Cloud and Data Hub (DHUB_CLOUD 2211)
  - Commerce Cloud (HY_COM 2205)
  - Commerce Cloud (COM_CLOUD 2211)
  - Commerce Cloud (2211-JDK21)
  - Fiori (launchpad) (SAP_UI 754)
  - Fiori (launchpad) (SAP_UI 755)
  - Fiori (launchpad) (SAP_UI 756)
  - Fiori (launchpad) (SAP_UI 757)
  - Fiori (launchpad) (SAP_UI 758)
  - Fiori (launchpad) (SAP_UI 816)
  - MDG (Review Match Groups Application) (S4CORE 108)
  - MDG (Review Match Groups Application) (SAP_BASIS 916)
  - MDG (Review Match Groups Application) (SAP_BASIS 917)
  - MDG (Review Match Groups Application) (SAP_ABA 816)
  - NetWeaver Application Server Java (Web Container) (ENGINEAPI 7.50)
  - NetWeaver AS ABAP and ABAP Platform (KRNL64NUC 7.22)
  - NetWeaver AS ABAP and ABAP Platform (KRNL64NUC 7.22EXT)
  - NetWeaver AS ABAP and ABAP Platform (KRNL64UC 7.22)
  - NetWeaver AS ABAP and ABAP Platform (KRNL64UC 722EXT)
  - NetWeaver AS ABAP and ABAP Platform (KRNL64UC 7.53)
  - NetWeaver AS ABAP and ABAP Platform (KERNEL 7.22)
  - NetWeaver AS ABAP and ABAP Platform (KERNEL 7.53)
  - NetWeaver AS ABAP and ABAP Platform (KERNEL 7.54)
  - NetWeaver AS ABAP and ABAP Platform (KERNEL 7.77)
  - NetWeaver AS ABAP and ABAP Platform (KERNEL 7.89)
  - NetWeaver AS ABAP and ABAP Platform (KERNEL 7.93)
  - NetWeaver AS ABAP and ABAP Platform (KERNEL 9.16)
  - NetWeaver AS ABAP and ABAP Platform (KERNEL 9.18)
  - NetWeaver AS ABAP and ABAP Platform (KERNEL 91.9)
  - NetWeaver AS ABAP and ABAP Platform (SAP_BASIS 700)
  - NetWeaver AS ABAP and ABAP Platform (SAP_BASIS 701)
  - NetWeaver AS ABAP and ABAP Platform (SAP_BASIS 702)
  - NetWeaver AS ABAP and ABAP Platform (SAP_BASIS 731)
  - NetWeaver AS ABAP and ABAP Platform (SAP_BASIS 740)
  - NetWeaver AS ABAP and ABAP Platform (SAP_BASIS 750)
  - NetWeaver AS ABAP and ABAP Platform (SAP_BASIS 751)
  - NetWeaver AS ABAP and ABAP Platform (SAP_BASIS 752)
  - NetWeaver AS ABAP and ABAP Platform (SAP_BASIS 753)
  - NetWeaver AS ABAP and ABAP Platform (SAP_BASIS 754)
  - NetWeaver AS ABAP and ABAP Platform (SAP_BASIS 755)
  - NetWeaver AS ABAP and ABAP Platform (SAP_BASIS 756)
  - NetWeaver AS ABAP and ABAP Platform (SAP_BASIS 757)
  - NetWeaver AS ABAP and ABAP Platform (SAP_BASIS 758)
  - NetWeaver AS ABAP and ABAP Platform (SAP_BASIS 816)
  - NetWeaver AS ABAP and ABAP Platform (SAP_BASIS 918)
  - NetWeaver AS ABAP and ABAP Platform (SAP_BASIS 919)
  - NetWeaver AS Java (JDBC Test Servlet) (BI_UDI 7.50)
  - NetWeaver AS Java (SERVERCORE 7.50)
  - NetWeaver AS Java (CORE-TOOLS 7.50)
  - NetWeaver AS Java (J2EE-APPS 7.50)
  - ODP Data Replication APIs (DW4CORE 200)
  - ODP Data Replication APIs (DW4CORE 300)
  - ODP Data Replication APIs (DW4CORE 400)
  - ODP Data Replication APIs (PI_BASIS 2006_1_700)
  - ODP Data Replication APIs (PI_BASIS 701)
  - ODP Data Replication APIs (PI_BASIS 702)
  - ODP Data Replication APIs (PI_BASIS 731)
  - ODP Data Replication APIs (PI_BASIS 740)
  - ODP Data Replication APIs (SAP_BW 750)
  - ODP Data Replication APIs (SAP_BW 816)
  - S/4HANA (S4FND 102)
  - S/4HANA (S4FND 103)
  - S/4HANA (S4FND 104)
  - S/4HANA (S4FND 105)
  - S/4HANA (S4FND 106)
  - S/4HANA (S4FND 107)
  - S/4HANA (S4FND 108)
  - S/4HANA (S4FND 109)
  - Wily Introscope Enterprise Manager (WILY_INTRO_ENTERPRISE 10.8)
  - SAP NetWeaver AS ABAP and ABAP Platform
  - SAP NetWeaver Application Server Java (Web Container)
  - SAP Commerce Cloud
  - SAP Data Hub version ENGINEAPI 7.50
  - Apache Tomcat < 10.1.53
  - Apache Tomcat < 9.0.116
  - Apache Tomcat < 11.0.20
  - Tomcat Native < 2.0.14
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0715/
  - https://support.sap.com/en/my-support/knowledge-base/security-notes-news/june-2026.html
  - https://www.cve.org/CVERecord?id=CVE-2025-68161
  - https://www.cve.org/CVERecord?id=CVE-2026-22732
  - https://www.cve.org/CVERecord?id=CVE-2026-24315
  - https://www.cve.org/CVERecord?id=CVE-2026-27671
  - https://www.cve.org/CVERecord?id=CVE-2026-29145
  - https://www.cve.org/CVERecord?id=CVE-2026-40128
  - https://www.cve.org/CVERecord?id=CVE-2026-44743
  - https://www.cve.org/CVERecord?id=CVE-2026-44744
  - https://www.cve.org/CVERecord?id=CVE-2026-44746
  - https://www.cve.org/CVERecord?id=CVE-2026-44748
  - https://www.cve.org/CVERecord?id=CVE-2026-44750
  - https://www.cve.org/CVERecord?id=CVE-2026-44751
  - https://www.cve.org/CVERecord?id=CVE-2026-44754
  - https://www.cve.org/CVERecord?id=CVE-2026-44755
  - https://www.cve.org/CVERecord?id=CVE-2026-44757
  - https://ccb.belgium.be/advisories/warning-sap-addresses-critical-vulnerabilities-affecting-multiple-sap-products-patch
  - https://sploitus.com/exploit?id=80A91C97-5EB0-566A-AB8F-52BAA4DC2EC6&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=80A91C97-5EB0-566A-AB8F-52BAA4DC2EC6
  - type: url
    value: https://github.com/apache/tomcat/commit/fe26667cd2385045ac73f4dea086cc9971209b90
  - type: url
    value: https://github.com/gkdgkd123/CVE-2026-29145-Everything.git
  - type: url
    value: http://ocsp-responder:8888
  - type: url
    value: https://127.0.0.1:8443/protected-resource/
ioc_counts:
  url: 5
rules:
  - title: Detects CVE-2026-22732 Exploitation — Web-based SQL Injection Attempt
    description: Detects CVE-2026-22732 exploitation - common SQL injection patterns in web request URI or query parameters targeting SAP applications.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
      - T1505.001
    data_sources:
      - webserver
  - title: Detects CVE-2026-44743 Exploitation — Web-based XSS Attempt
    description: Detects CVE-2026-44743 exploitation - common Cross-Site Scripting (XSS) patterns in web request URI or query parameters targeting SAP applications.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
rules_count: 2
updates:
  - at: "2026-06-14T09:46:16Z"
    level: L2
    summary: added CVE-2026-40128 +2
    sources:
      - ccb-belgium
  - at: "2026-07-11T09:01:20Z"
    level: L1
    summary: new IOCs
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=80A91C97-5EB0-566A-AB8F-52BAA4DC2EC6&utm_source=rss&utm_medium=rss
---

CERT-FR has issued an advisory detailing multiple high-severity vulnerabilities discovered across numerous SAP products. These vulnerabilities, disclosed in SAP's June 2026 Security Bulletin, include critical flaws such as SQL Injection (SQLi), remote indirect code injection (Cross-Site Scripting - XSS), and security policy bypasses. These issues affect core SAP components like Business Objects, Commerce Cloud, Fiori, MDG, NetWeaver, ODP Data Replication APIs, S/4HANA, and Wily Introscope Enterprise Manager. If exploited, these flaws could allow attackers to gain unauthorized access to sensitive data, bypass security controls, and potentially execute arbitrary code, leading to significant compromise of critical enterprise systems and data. Organizations utilizing these unpatched SAP products are strongly advised to apply the security updates immediately.

## Attack Chain

1.  **Reconnaissance**: An attacker identifies internet-facing or internal SAP applications and their versions, leveraging OSINT or network scanning to pinpoint vulnerable SAP product instances susceptible to known CVEs.
2.  **Exploitation (SQL Injection)**: The attacker crafts and sends malicious HTTP requests containing SQL payloads targeting specific parameters or input fields in SAP web applications, exploiting SQLi vulnerabilities (e.g., CVE-2026-22732, CVE-2026-24315).
3.  **Data Exfiltration / Database Command Execution**: Successful SQLi grants the attacker unauthorized access to query the underlying database for sensitive information (e.g., user credentials, business data) or, depending on the specific vulnerability, execute arbitrary commands on the database server.
4.  **Exploitation (Cross-Site Scripting - XSS)**: The attacker injects malicious JavaScript into vulnerable SAP application inputs or parameters, which is then reflected or stored (e.g., CVE-2026-44743, CVE-2026-44744).
5.  **Client-Side Compromise**: When a legitimate user accesses the vulnerable SAP page, the malicious script executes in their browser, potentially leading to session hijacking, credential theft via phishing, or redirection to attacker-controlled sites.
6.  **Exploitation (Security Policy Bypass)**: The attacker discovers and leverages flaws in authorization or access control mechanisms (e.g., CVE-2025-68161, CVE-2026-44746) to bypass security policies or gain elevated permissions.
7.  **Unauthorized Access to Sensitive Functions**: Successful policy bypass grants the attacker access to privileged functions or data within the SAP application that would otherwise be restricted, allowing for unauthorized actions.
8.  **Further System Compromise / Data Manipulation**: Leveraging these vulnerabilities, the attacker can achieve unauthorized data manipulation, further privilege escalation, establish persistence, or compromise the integrity of business-critical data.

## Impact

Successful exploitation of these vulnerabilities could lead to severe consequences for affected organizations. Attackers could gain unauthorized access to sensitive business data, including customer records, financial information, and intellectual property. The compromise of critical business processes hosted on SAP systems could result in significant operational disruption. Furthermore, the ability to execute arbitrary code via SQL injection could lead to complete system compromise, allowing attackers to establish persistence or pivot to other systems. Client-side attacks resulting from XSS could lead to credential theft, session hijacking, or the delivery of malware to end-users. The cumulative impact includes potential data breaches, financial losses, severe reputational damage, and non-compliance with regulatory requirements.

## Recommendation

*   Immediately apply all security patches released by SAP on June 9, 2026, as detailed in the SAP Security Bulletin linked in this brief, to address CVE-2025-68161, CVE-2026-22732, and others.
*   Enable comprehensive web server logging for all internet-facing SAP applications to monitor for suspicious HTTP request patterns that may indicate SQLi or XSS attempts.
*   Deploy the provided Sigma rules for "Detects CVE-2026-22732 Exploitation — Web-based SQL Injection Attempt" and "Detects CVE-2026-44743 Exploitation — Web-based XSS Attempt" to your SIEM and tune them for your environment.
*   Implement and enforce robust input validation and output encoding mechanisms across all SAP web applications to mitigate SQLi and XSS vulnerabilities.
*   Regularly review and audit access controls and security policies within SAP environments to identify and address potential bypass vulnerabilities.
