---
title: brikcss merge Prototype Pollution Vulnerability (CVE-2026-6594)
slug: 2026-04-brikcss-prototype-pollution
description: A prototype pollution vulnerability (CVE-2026-6594) in brikcss merge up to version 1.3.0 allows remote attackers to modify object prototype attributes by manipulating the __proto__/constructor.prototype/prototype argument.
date: "2026-04-20T02:16:15Z"
severities:
  - high
tags:
  - prototype-pollution
  - javascript
  - code-injection
  - cve-2026-6594
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
cves:
  - id: CVE-2026-6594
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6594
  - https://github.com/sudo-secure/security-research/blob/main/brikcss-merge/prototype-pollution/PoC.md
  - https://vuldb.com/vuln/358229
rules:
  - title: Detect Prototype Pollution via HTTP Request
    description: Detects HTTP requests attempting to exploit prototype pollution vulnerabilities by injecting __proto__ or constructor.prototype properties.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1547.001
    data_sources:
      - webserver
      - linux
  - title: Detect Prototype Pollution via POST Body
    description: Detects HTTP requests with POST bodies attempting to exploit prototype pollution by injecting __proto__ or constructor.prototype properties.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1547.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A prototype pollution vulnerability, identified as CVE-2026-6594, affects brikcss merge versions up to 1.3.0. This vulnerability allows a remote attacker to manipulate the __proto__/constructor.prototype/prototype argument, leading to the modification of object prototype attributes. The vendor was notified, but did not respond. Successful exploitation can lead to denial of service, code injection, or other unintended behaviors in applications using the affected library. Prototype pollution…
