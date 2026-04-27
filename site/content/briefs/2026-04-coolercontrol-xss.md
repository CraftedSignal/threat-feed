---
title: CoolerControl-UI Stored XSS Vulnerability (CVE-2026-5301)
slug: 2026-04-coolercontrol-xss
description: Unauthenticated attackers can perform a stored XSS attack against CoolerControl/coolercontrol-ui versions less than 4.0.0 by injecting malicious JavaScript into log entries, leading to potential service takeover.
date: "2026-04-08T13:16:43Z"
severities:
  - high
tags:
  - xss
  - cve-2026-5301
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5301
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5301
  - https://gitlab.com/coolercontrol/coolercontrol/-/blob/2.0.0/coolercontrol-ui/src/views/AppInfoView.vue?ref_type=tags#L224
  - https://gitlab.com/coolercontrol/coolercontrol/-/blob/3.1.1/coolercontrol-ui/src/views/AppInfoView.vue?ref_type=tags#L350
  - https://gitlab.com/coolercontrol/coolercontrol/-/releases/4.0.0
rules:
  - title: Detect Potential XSS in CoolerControl-UI Logs
    description: Detects potential cross-site scripting (XSS) attempts in CoolerControl-UI log entries by looking for common JavaScript injection patterns.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Script Tags in HTTP Response (CoolerControl-UI)
    description: Detects script tags in HTTP response bodies, potentially indicating an XSS vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CoolerControl/coolercontrol-ui versions prior to 4.0.0 are vulnerable to a stored Cross-Site Scripting (XSS) vulnerability identified as CVE-2026-5301. This flaw resides in the log viewer component of the application. Unauthenticated attackers can exploit this vulnerability by injecting malicious JavaScript code into log entries. When a user views the log entries containing the malicious script, the script executes within their browser, potentially allowing the attacker to take over the…
