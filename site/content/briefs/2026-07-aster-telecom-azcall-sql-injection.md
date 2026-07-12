---
title: SQL Injection Vulnerability in Aster Telecom Azcall (CVE-2026-15482)
slug: 2026-07-aster-telecom-azcall-sql-injection
description: A critical SQL injection vulnerability, tracked as CVE-2026-15482, exists in Aster Telecom Azcall 10/11 within the HTTP Handler component, where manipulating the 'nome/perfil/status' argument when accessing '/azcall/adm/gestao_loja/sis.php?t=consultar' can lead to remote SQL injection, with a publicly available exploit allowing unauthenticated attackers to potentially access or modify sensitive data.
date: "2026-07-12T07:19:46Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-vulnerability
  - cve
  - exploit-available
vendors:
  - Aster Telecom
products:
  - Azcall 10/11
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be performed from remote. The exploit has been made available to the public and could be used for attacks.
    confidence_band: high
cves:
  - id: CVE-2026-15482
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15482
rules:
  - title: Detects CVE-2026-15482 Exploitation - SQL Injection in Aster Telecom Azcall
    description: Detects attempts to exploit CVE-2026-15482 by injecting SQL into the 'nome', 'perfil', or 'status' arguments of the '/azcall/adm/gestao_loja/sis.php?t=consultar' endpoint.
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

A significant SQL injection vulnerability, identified as CVE-2026-15482, has been discovered in Aster Telecom Azcall versions 10 and 11. This flaw resides within the application's HTTP Handler component, specifically affecting the processing of input to the file `/azcall/adm/gestao_loja/sis.php?t=consultar`. Attackers can remotely exploit this weakness by manipulating the `nome`, `perfil`, or `status` arguments in the URL query string to inject malicious SQL commands. The vulnerability has a CVSS v3.1 Base Score of 7.3, indicating high severity. Crucially, a public exploit for this vulnerability is available, making it accessible for immediate use by malicious actors. The vendor, Aster Telecom, was notified prior to public disclosure but has reportedly not responded. This poses a substantial risk to organizations using affected Azcall instances, as unauthenticated attackers can gain unauthorized access to or modify sensitive database information.

## Attack Chain

1. **Reconnaissance:** An attacker identifies an internet-facing instance of Aster Telecom Azcall 10/11, potentially through scanning or public search engines.
2. **Vulnerability Identification:** The attacker leverages knowledge of CVE-2026-15482 and its publicly available exploit details, understanding the SQL injection flaw within the `/azcall/adm/gestao_loja/sis.php` endpoint.
3. **Malicious HTTP Request Crafting:** The attacker constructs a specially crafted HTTP GET request targeting the vulnerable endpoint `/azcall/adm/gestao_loja/sis.php?t=consultar`.
4. **SQL Payload Injection:** An SQL injection payload is embedded within one of the `nome`, `perfil`, or `status` URL query parameters of the crafted HTTP GET request.
5. **Unsanitized Input Processing:** The vulnerable HTTP Handler component of Azcall receives and processes the request without adequately validating or sanitizing the malicious input.
6. **Backend Database Execution:** The injected SQL payload is executed directly by the backend database, resulting in unauthorized query execution.
7. **Unauthorized Data Access/Manipulation:** The attacker gains unauthorized access to sensitive database information, potentially leading to data exfiltration, modification, or deletion, depending on the injected payload.

## Impact

Successful exploitation of CVE-2026-15482 can lead to severe consequences, primarily unauthorized access to and manipulation of the backend database. This includes the potential for full data exfiltration, modification of critical system records, or even deletion of database contents, resulting in data breaches, data loss, and operational disruption. Given the publicly available exploit, all unpatched Aster Telecom Azcall 10/11 instances are at high risk of compromise, potentially exposing customer data, configuration details, or other sensitive organizational information to unauthorized parties. The lack of vendor response further exacerbates the risk, leaving affected organizations without an official patch.

## Recommendation

* **Implement WAF Rules:** Deploy web application firewall (WAF) rules to detect and block SQL injection attempts targeting the `/azcall/adm/gestao_loja/sis.php` endpoint and its parameters (`nome`, `perfil`, `status`).
* **Monitor Webserver Logs:** Continuously monitor webserver access logs for suspicious HTTP GET requests to `/azcall/adm/gestao_loja/sis.php?t=consultar` containing SQL injection patterns in the URL query string to activate the rule below.
* **Vulnerability Scanning:** Conduct regular vulnerability scanning on all internet-facing web applications to identify and remediate similar web vulnerabilities.
* **Patching:** Apply any future patches released by Aster Telecom for CVE-2026-15482 immediately upon availability.
