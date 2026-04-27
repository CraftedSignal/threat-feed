---
title: WeGIA SQL Injection Vulnerability (CVE-2026-40285)
slug: 2026-04-wegia-sqli
description: WeGIA versions prior to 3.6.10 are vulnerable to SQL injection via the cpf_usuario POST parameter, allowing authenticated users to query the database under an arbitrary identity.
date: "2026-04-18T12:00:00Z"
severities:
  - high
tags:
  - wegia
  - sql-injection
  - cve-2026-40285
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-40285
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40285
rules:
  - title: Detect WeGIA SQL Injection Attempt via cpf_usuario Parameter
    description: Detects potential SQL injection attempts in WeGIA by monitoring HTTP POST requests with suspicious payloads in the cpf_usuario parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect WeGIA SQL Injection Attempt via cpf_usuario Parameter - Error Based
    description: Detects potential SQL injection attempts in WeGIA by monitoring HTTP POST requests with error inducing payloads in the cpf_usuario parameter.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

WeGIA, a web manager for charitable institutions, is susceptible to a SQL injection vulnerability affecting versions prior to 3.6.10. This flaw, identified as CVE-2026-40285, resides in the `dao/memorando/UsuarioDAO.php` file. The vulnerability stems from the insecure handling of the `cpf_usuario` POST parameter within the `DespachoControle::verificarDespacho()` function, where the `extract($_REQUEST)` function overwrites the session-stored user identity. An attacker can then manipulate the…
