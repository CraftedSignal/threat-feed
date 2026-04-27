---
title: Across DR-810 Unauthenticated File Disclosure Vulnerability
slug: 2026-04-across-dr810-file-disclosure
description: Across DR-810 routers are vulnerable to unauthenticated file disclosure, allowing remote attackers to download the rom-0 backup file containing sensitive information, such as router passwords and configuration data, via a simple GET request to the rom-0 endpoint.
date: "2026-04-12T13:16:33Z"
severities:
  - critical
tags:
  - cve-2019-25706
  - file-disclosure
  - router
  - network
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2019-25706
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25706
  - http://www.ac.i8i.ir/
  - https://www.exploit-db.com/exploits/46132
  - https://www.vulncheck.com/advisories/across-dr-810-rom-0-unauthenticated-file-disclosure
ioc_counts:
  email: 1
  url: 3
rules:
  - title: Across DR-810 Rom-0 File Disclosure Attempt
    description: Detects attempts to download the rom-0 backup file from Across DR-810 routers.
    platform: sigma
    severity: critical
    tactics:
      - discovery
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
  - title: Across DR-810 Rom-0 File Download Response
    description: Detects successful downloads of the rom-0 backup file from Across DR-810 routers based on response size.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Across DR-810 router contains an unauthenticated file disclosure vulnerability (CVE-2019-25706) that allows remote attackers to retrieve sensitive information. By sending a simple GET request to the `/rom-0` endpoint, an attacker can download a backup file containing router passwords, configuration details, and potentially other sensitive data. This vulnerability exists because the `/rom-0` endpoint does not require authentication, allowing anyone with network access to the router to…
