---
title: Metasoft MetaCRM SQL Injection Vulnerability (CVE-2026-15514)
slug: 2026-07-metacrm-sqli
description: A critical SQL injection vulnerability (CVE-2026-15514) in Metasoft MetaCRM up to version 6.4.0 Beta06 allows remote attackers to exploit the RPCService.query function via the phprpc_args argument in /customizemt/xkq/rpc.jsp, leading to unauthorized database access and manipulation, with a public exploit available.
date: "2026-07-13T00:18:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-vulnerability
  - crm
  - remote-code-execution
vendors:
  - Metasoft 美特软件
products:
  - MetaCRM up to 6.4.0 Beta06
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This vulnerability affects the function RPCService.query of the file /customizemt/xkq/rpc.jsp of the component PHPRPC Remote Call Interface. Executing a manipulation of the argument phprpc_args can lead to sql injection. The attack can be launched remotely.
    confidence_band: high
cves:
  - id: CVE-2026-15514
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15514
rules:
  - title: Detects CVE-2026-15514 Exploitation - Metasoft MetaCRM SQL Injection
    description: Detects exploitation attempts of CVE-2026-15514, a SQL injection vulnerability in Metasoft MetaCRM, by identifying suspicious POST requests to /customizemt/xkq/rpc.jsp with SQL keywords in the phprpc_args parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A high-severity SQL injection vulnerability, tracked as CVE-2026-15514, has been identified in Metasoft MetaCRM software, affecting versions up to 6.4.0 Beta06. This weakness resides within the `RPCService.query` function of the `/customizemt/xkq/rpc.jsp` component, which is part of the PHPRPC Remote Call Interface. Attackers can remotely exploit this flaw by manipulating the `phprpc_args` argument, injecting malicious SQL queries. This can lead to unauthorized access, modification, or exfiltration of sensitive data from the underlying database. A public exploit for this vulnerability is available, increasing the immediate risk of attacks. The vendor, Metasoft 美特软件, was notified of this vulnerability but has not yet responded to the disclosure. Organizations using affected MetaCRM versions are at significant risk of data breaches and system compromise if this vulnerability remains unpatched.

## Attack Chain

1. An attacker identifies a vulnerable Metasoft MetaCRM instance exposed to the internet.
2. The attacker crafts a specially malformed `phprpc_args` parameter containing SQL injection payload.
3. The attacker sends an HTTP POST request to the `/customizemt/xkq/rpc.jsp` endpoint on the vulnerable server, including the malicious `phprpc_args` parameter.
4. The server's `RPCService.query` function within the `PHPRPC Remote Call Interface` processes the request without proper sanitization.
5. The injected SQL commands are executed by the backend database, leading to unauthorized data access or manipulation.
6. The attacker gains access to sensitive database information, potentially leading to data exfiltration or further system compromise.

## Impact

Successful exploitation of CVE-2026-15514 can result in significant data compromise. Attackers can gain unauthorized read and write access to the MetaCRM database, potentially exfiltrating sensitive customer information, financial data, or internal business records. Manipulation of database content could lead to data integrity issues, service disruption, or even administrative account compromise if credentials are stored insecurely. The widespread use of MetaCRM in various sectors means that a successful attack could impact numerous organizations, resulting in financial losses, reputational damage, and regulatory penalties. The public availability of an exploit significantly escalates the threat level, making immediate action crucial for all affected organizations.

## Recommendation

* Deploy the Sigma rule provided in this brief to your SIEM to detect exploitation attempts against CVE-2026-15514.
* Monitor web server logs (`category: webserver`) for suspicious POST requests to `/customizemt/xkq/rpc.jsp` containing SQL injection patterns in the query string.
* Apply any available patches or updates from Metasoft 美特软件 addressing CVE-2026-15514 as soon as they are released. In the absence of an official patch, consider implementing a Web Application Firewall (WAF) to filter malicious input to the `/customizemt/xkq/rpc.jsp` endpoint.
