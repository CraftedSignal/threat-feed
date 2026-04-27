---
title: Tenda 4G03 Pro Improper Access Control Vulnerability (CVE-2026-5526)
slug: 2026-04-tenda-4g03-pro-access-control
description: CVE-2026-5526 describes an improper access control vulnerability in the Tenda 4G03 Pro router's /bin/httpd file, allowing remote attackers to potentially gain unauthorized access.
date: "2026-04-04T23:16:44Z"
severities:
  - high
tags:
  - cve-2026-5526
  - tenda
  - router
  - access-control
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5526
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5526
  - https://vuldb.com/vuln/355279
  - https://vuldb.com/vuln/355279/cti
  - https://www.tenda.com.cn/
rules:
  - title: Detect Suspicious HTTP Request to Tenda /bin/httpd
    description: Detects suspicious HTTP requests targeting the /bin/httpd file on Tenda routers, potentially indicating exploitation attempts related to CVE-2026-5526.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Unusual Process Spawning from Web Server on Tenda Router
    description: Detects unusual processes spawned from the web server process, potentially indicating command execution after exploiting CVE-2026-5526 on Tenda routers.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A security vulnerability, identified as CVE-2026-5526, affects the Tenda 4G03 Pro router, specifically versions up to 1.0/1.1/04.03.01.53/192.168.0.1. The flaw resides within an unspecified function of the `/bin/httpd` file, leading to improper access controls. A remote attacker could exploit this vulnerability, potentially gaining unauthorized access to the device. Publicly available exploits exist, increasing the risk of exploitation. This issue was reported on April 4, 2026, and poses a…
