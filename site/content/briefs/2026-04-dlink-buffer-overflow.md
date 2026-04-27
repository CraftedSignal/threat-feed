---
title: D-Link DIR-645 Stack-Based Buffer Overflow Vulnerability (CVE-2026-5815)
slug: 2026-04-dlink-buffer-overflow
description: A remote stack-based buffer overflow vulnerability exists in the hedwigcgi_main function of the /cgi-bin/hedwig.cgi file on D-Link DIR-645 routers (versions 1.01, 1.02, and 1.03), potentially allowing unauthenticated attackers to execute arbitrary code.
date: "2026-04-09T00:16:20Z"
severities:
  - critical
tags:
  - cve-2026-5815
  - buffer-overflow
  - d-link
  - router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5815
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5815
  - https://github.com/Pers1st0/CVE/blob/main/stack-based%20buffer%20overflow%20vulnerability%20exists%20in%20the%20hedwig.cgi%20of%20D-Link%20DIR-645.md
  - https://vuldb.com/vuln/356263
rules:
  - title: D-Link DIR-645 Buffer Overflow Attempt
    description: Detects potential buffer overflow attempts targeting the /cgi-bin/hedwig.cgi endpoint on D-Link DIR-645 routers.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: D-Link DIR-645 Unauthorized Access Attempt via hedwig.cgi
    description: Detects attempts to access the hedwig.cgi endpoint, potentially indicating exploitation of CVE-2026-5815 or other vulnerabilities.
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

CVE-2026-5815 describes a stack-based buffer overflow vulnerability affecting D-Link DIR-645 routers running firmware versions 1.01, 1.02, and 1.03. The vulnerability resides within the `hedwigcgi_main` function in the `/cgi-bin/hedwig.cgi` file.  Successful exploitation of this flaw could allow a remote, unauthenticated attacker to execute arbitrary code on the affected device. This vulnerability is particularly critical because a public exploit is available, increasing the likelihood of…
