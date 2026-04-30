---
title: perfree go-fastdfs-web Improper Authorization Vulnerability (CVE-2026-6105)
slug: 2026-04-go-fastdfs-web-authz-bypass
description: CVE-2026-6105 is a critical vulnerability in perfree go-fastdfs-web versions up to 1.3.7, allowing for remote improper authorization due to a flaw in the doInstall Interface, potentially leading to unauthorized system access and control.
date: "2026-04-11T22:16:01Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - CVE-2026-6105
  - Improper Authorization
  - go-fastdfs-web
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
cves:
  - id: CVE-2026-6105
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6105
  - https://gitee.com/ying-xiujie/cve/issues/IGB6M9
  - https://vuldb.com/vuln/356964
rules:
  - title: Detect Suspicious doInstall Interface Access
    description: Detects suspicious access attempts to the doInstall interface in perfree go-fastdfs-web, indicative of CVE-2026-6105 exploitation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - webserver
      - linux
  - title: Detect Unauthorized Access to InstallController.java
    description: Detects unauthorized access attempts to InstallController.java, which may indicate an attempt to exploit CVE-2026-6105
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical security vulnerability, CVE-2026-6105, has been identified in perfree go-fastdfs-web, affecting versions up to 1.3.7. The vulnerability resides in the `src/main/java/com/perfree/controller/InstallController.java` file, specifically within the `doInstall` Interface component. This flaw allows for improper authorization, enabling remote attackers to potentially bypass security measures and gain unauthorized access. The exploit has been publicly disclosed, increasing the risk of exploitation. The vendor was notified but has not responded, exacerbating the potential impact. Defenders should prioritize detection and mitigation efforts to prevent unauthorized access.

## Attack Chain

1.  Attacker identifies a vulnerable perfree go-fastdfs-web instance running a version up to 1.3.7.
2.  The attacker crafts a malicious request targeting the `doInstall` interface.
3.  The crafted request exploits the improper authorization vulnerability (CVE-2026-6105) in `InstallController.java`.
4.  The application fails to properly validate the attacker's privileges.
5.  The attacker gains unauthorized access to sensitive functionalities due to the bypassed authorization checks.
6.  The attacker performs unauthorized actions, such as modifying system settings or accessing restricted data.
7.  The attacker may leverage the initial access to further compromise the system or network.

## Impact

Successful exploitation of CVE-2026-6105 allows an unauthenticated remote attacker to bypass authorization controls in perfree go-fastdfs-web. The impact includes potential unauthorized access to sensitive data, modification of system configurations, and complete system compromise. Given the public disclosure of the exploit, organizations using affected versions of perfree go-fastdfs-web are at high risk of attack. The lack of vendor response further amplifies the threat.

## Recommendation

*   Deploy the Sigma rule `Detect Suspicious doInstall Interface Access` to identify unauthorized access attempts to the vulnerable endpoint (logsource: webserver, product: linux).
*   Monitor web server logs for suspicious requests targeting the `doInstall` interface in `InstallController.java` (logsource: webserver, product: linux).
*   Apply input validation and authorization checks to the `doInstall` Interface in `InstallController.java` to mitigate CVE-2026-6105.
*   Consider implementing a Web Application Firewall (WAF) rule to block requests matching the exploit pattern.
