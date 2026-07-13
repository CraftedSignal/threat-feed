---
title: Remote SQL Injection Vulnerability in Jinher OA 1.0 (CVE-2026-15517)
slug: 2026-07-jinher-oa-sql-injection
description: A remote SQL injection vulnerability, CVE-2026-15517, has been discovered in Jinher OA 1.0, allowing unauthenticated attackers to execute arbitrary SQL commands by manipulating the `httpOID` argument in the `/C6/JHSoft.Web.PlanSummarize/PlanGiveOut.aspx` file, with a public exploit available.
date: "2026-07-13T01:19:24Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - sql-injection
  - web-application
  - vulnerability
  - cve
  - remote-code-execution
vendors:
  - Jinher
products:
  - OA 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Remote exploitation of the attack is possible. The exploit has been published and may be used.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
    evidence: This manipulation of the argument httpOID causes sql injection.
    confidence_band: high
cves:
  - id: CVE-2026-15517
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15517
  - https://github.com/weini587/CVE/issues/1
  - https://vuldb.com/cve/CVE-2026-15517
  - https://vuldb.com/submit/849470
  - https://vuldb.com/vuln/377846
  - https://vuldb.com/vuln/377846/cti
iocs:
  - type: url
    value: https://github.com/weini587/CVE/issues/1
  - type: url
    value: https://vuldb.com/cve/CVE-2026-15517
  - type: url
    value: https://vuldb.com/submit/849470
  - type: url
    value: https://vuldb.com/vuln/377846
  - type: url
    value: https://vuldb.com/vuln/377846/cti
ioc_counts:
  url: 5
rules:
  - title: Detects CVE-2026-15517 Exploitation - Jinher OA SQL Injection
    description: Detects exploitation attempts of CVE-2026-15517 in Jinher OA 1.0, specifically SQL injection via the 'httpOID' argument in the PlanGiveOut.aspx file.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.003
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A significant security flaw, tracked as CVE-2026-15517, exists in Jinher OA 1.0, specifically impacting the `/C6/JHSoft.Web.PlanSummarize/PlanGiveOut.aspx` file. This vulnerability stems from improper neutralization of special elements in the `httpOID` argument, leading to a blind SQL injection. Attackers can remotely exploit this weakness without authentication, granting them the ability to execute arbitrary SQL commands on the underlying database. The vulnerability has been publicly disclosed, and an exploit has been published, significantly increasing the risk of active exploitation. The vendor, Jinher, was reportedly notified prior to public disclosure but did not respond. This vulnerability poses a critical risk to organizations using Jinher OA 1.0, as it can lead to unauthorized data access, modification, or potential full system compromise depending on the database configuration and privileges.

## Attack Chain

1. An unauthenticated attacker identifies a public-facing Jinher OA 1.0 instance, often by scanning for known application paths or components.
2. The attacker crafts a specially malformed HTTP GET or POST request targeting the `PlanGiveOut.aspx` endpoint located at `/C6/JHSoft.Web.PlanSummarize/PlanGiveOut.aspx`.
3. The request includes a malicious SQL injection payload within the `httpOID` argument. This payload is designed to manipulate the application's database queries.
4. The Jinher OA 1.0 application processes the request without adequately sanitizing the `httpOID` input, leading to the execution of the attacker's embedded SQL commands.
5. Depending on the SQL injection payload, the attacker can extract sensitive data from the database, modify database records, or potentially execute operating system commands if the database user has sufficient privileges (e.g., via `xp_cmdshell` in Microsoft SQL Server).
6. The attacker consolidates access, exfiltrates sensitive information, or establishes persistence on the compromised server.
7. The final objective typically involves data exfiltration, unauthorized administrative access, or further lateral movement within the compromised network.

## Impact

Successful exploitation of CVE-2026-15517 can lead to severe consequences for organizations utilizing Jinher OA 1.0. Attackers can gain unauthorized access to sensitive information stored in the application's database, including user credentials, proprietary business data, and personal identifiable information (PII). Data integrity can be compromised through unauthorized modification or deletion of records. Depending on the database configuration and privileges, remote code execution may be possible, leading to full system compromise of the server hosting Jinher OA 1.0. The public availability of an exploit significantly lowers the bar for attackers, increasing the likelihood of widespread exploitation and data breaches.

## Recommendation

* Patch CVE-2026-15517 on all Jinher OA 1.0 installations immediately upon availability of a vendor fix.
* Deploy the Sigma rule "Detects CVE-2026-15517 Exploitation - Jinher OA SQL Injection" to your SIEM to identify attempts to exploit this vulnerability.
* Monitor web server access logs for suspicious requests to `/C6/JHSoft.Web.PlanSummarize/PlanGiveOut.aspx` containing SQL injection payloads in the `httpOID` parameter.
* Implement Web Application Firewalls (WAFs) to filter and block common SQL injection patterns in web requests to protect against exploitation of CVE-2026-15517.
* Review network connection logs for outbound connections from the Jinher OA server that could indicate data exfiltration or command and control activity post-exploitation.
