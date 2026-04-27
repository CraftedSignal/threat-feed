---
title: Tenda CH22 Router Stack-Based Buffer Overflow Vulnerability
slug: 2026-04-tenda-ch22-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-5604) in Tenda CH22 1.0.0.1 allows remote attackers to execute arbitrary code by manipulating the 'standard' argument in the formCertLocalPrecreate function of the /goform/CertLocalPrecreate file within the Parameter Handler component.
date: "2026-04-05T23:16:20Z"
severities:
  - critical
tags:
  - cve-2026-5604
  - buffer-overflow
  - tenda
  - router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5604
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5604
  - https://github.com/Litengzheng/vuldb_new/blob/main/CH22/vul_52/README.md
  - https://vuldb.com/vuln/355396
rules:
  - title: Detect Tenda CH22 Buffer Overflow Attempt via Long Standard Parameter
    description: Detects potential exploitation attempts of the Tenda CH22 stack-based buffer overflow vulnerability by monitoring for abnormally long 'standard' parameters in requests to the /goform/CertLocalPrecreate endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda CH22 Router POST Request to CertLocalPrecreate
    description: Detects POST requests to the /goform/CertLocalPrecreate endpoint of Tenda CH22 routers, which could indicate an attempt to exploit CVE-2026-5604.
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

CVE-2026-5604 details a critical security vulnerability affecting Tenda CH22 router version 1.0.0.1. The vulnerability is a stack-based buffer overflow located in the `formCertLocalPrecreate` function within the `/goform/CertLocalPrecreate` file, which handles parameters. Attackers can exploit this flaw by manipulating the `standard` argument. The vulnerability can be triggered remotely, meaning an attacker does not need local access to the device. Given that a public exploit is available, this…
