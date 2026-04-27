---
title: Tenda F456 Router Buffer Overflow Vulnerability (CVE-2026-7101)
slug: 2026-04-tenda-f456-buffer-overflow
description: A buffer overflow vulnerability in Tenda F456 version 1.0.0.5 allows remote attackers to execute arbitrary code via a crafted request to the fromWrlclientSet function in the /goform/WrlclientSet file of the httpd component.
date: "2026-04-27T09:19:31Z"
severities:
  - critical
tags:
  - cve-2026-7101
  - buffer-overflow
  - router
  - tenda
  - remote-code-execution
vendors:
  - Tenda
products:
  - F456 (1.0.0.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7101
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7101
  - https://github.com/Litengzheng/vuldb_new/blob/main/F456/vul_139/README.md
  - https://vuldb.com/vuln/359676
rules:
  - title: Detect Tenda F456 Buffer Overflow Attempt via URI
    description: Detects potential buffer overflow exploit attempts targeting the /goform/WrlclientSet endpoint on Tenda F456 routers based on suspicious URI length.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda F456 Buffer Overflow Attempt via POST Request
    description: Detects potential buffer overflow exploit attempts targeting the /goform/WrlclientSet endpoint on Tenda F456 routers based on POST requests with long request bodies.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical buffer overflow vulnerability, identified as CVE-2026-7101, has been discovered in Tenda F456 router version 1.0.0.5. The vulnerability resides in the `fromWrlclientSet` function within the `/goform/WrlclientSet` file, which is part of the router's httpd component. Successful exploitation allows remote attackers to execute arbitrary code on the device. Publicly available exploit code exists, increasing the risk of widespread exploitation. This vulnerability poses a significant threat…
