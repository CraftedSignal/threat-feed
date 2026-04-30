---
title: Out-of-bounds Read Vulnerability in fabiangreffrath woof (CVE-2026-4750)
slug: 2026-03-woof-oob-read
description: CVE-2026-4750 is a critical out-of-bounds read vulnerability affecting fabiangreffrath woof versions before 15.3.0, potentially leading to information disclosure or denial of service.
date: "2026-03-24T06:16:23Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-4750
  - out-of-bounds read
  - webserver
  - woof
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Information Discovery
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4750
  - https://github.com/fabiangreffrath/woof/pull/2521
rules:
  - title: Detect Woof Out-of-Bounds Read Attempt
    description: Detects potential exploitation attempts of CVE-2026-4750 in woof by identifying suspicious HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Woof Out-of-Bounds Read Attempt (Path Traversal)
    description: Detects potential exploitation attempts of CVE-2026-4750 in woof by identifying suspicious HTTP requests with path traversal.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

An out-of-bounds read vulnerability exists in fabiangreffrath woof, a web server for simple file sharing. This vulnerability, identified as CVE-2026-4750, affects woof versions prior to 15.3.0. The vulnerability was reported by the Government Technology Agency of Singapore Cyber Security Group (GovTech CSG). An attacker could potentially exploit this vulnerability to read sensitive information from the server's memory or cause a denial-of-service condition. This poses a risk to organizations…
