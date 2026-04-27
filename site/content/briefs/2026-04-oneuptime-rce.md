---
title: OneUptime Unauthenticated Endpoint Access Vulnerability (CVE-2026-34758)
slug: 2026-04-oneuptime-rce
description: OneUptime versions prior to 10.0.42 are vulnerable to unauthenticated access to Notification test and Phone Number management endpoints, leading to potential abuse of SMS, Call, Email, and WhatsApp functionalities, and unauthorized phone number purchases, fixed in version 10.0.42.
date: "2026-04-02T19:21:33Z"
severities:
  - critical
tags:
  - cve
  - vulnerability
  - oneuptime
  - unauthenticated-access
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34758
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34758
  - https://github.com/OneUptime/oneuptime/commit/9adbd04538714740506708d6fa610e433be4d2a4
  - https://github.com/OneUptime/oneuptime/releases/tag/10.0.42
  - https://github.com/OneUptime/oneuptime/security/advisories/GHSA-q253-6wcm-h8hp
ioc_counts:
  email: 1
rules:
  - title: Detect Unauthenticated OneUptime Notification Test Access
    description: Detects unauthenticated access attempts to the OneUptime notification test endpoint, indicative of CVE-2026-34758 exploitation.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Unauthenticated OneUptime Phone Number Purchase Access
    description: Detects unauthenticated access attempts to the OneUptime phone number purchase endpoint, indicative of CVE-2026-34758 exploitation.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OneUptime, an open-source monitoring and observability platform, is susceptible to a critical vulnerability (CVE-2026-34758) affecting versions prior to 10.0.42. This vulnerability stems from the lack of authentication on critical Notification test and Phone Number management endpoints. Exploitation of this flaw could enable attackers to abuse SMS, call, email, and WhatsApp functionalities, potentially sending unsolicited messages or incurring costs for the affected organization. Furthermore…
