---
title: Suricata NULL Dereference Vulnerability
slug: 2026-04-suricata-null-dereference
description: Suricata versions 8.0.0 to before 8.0.4 are vulnerable to a NULL dereference crash when using the 'tls.alpn' rule keyword, potentially leading to a denial of service.
date: "2026-04-02T14:16:28Z"
severities:
  - medium
tags:
  - suricata
  - denial-of-service
  - null-dereference
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
cves:
  - id: CVE-2026-31931
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-31931
  - https://github.com/OISF/suricata/security/advisories/GHSA-gr22-4784-xvw3
  - https://redmine.openinfosecfoundation.org/issues/8294
ioc_counts:
  email: 2
rules:
  - title: Suricata Process Crash Due to SIGSEGV
    description: Detects Suricata process crashing due to a segmentation fault (SIGSEGV), which could be caused by CVE-2026-31931.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - process_creation
      - linux
  - title: Suricata Rule Load with tls.alpn Keyword
    description: Detects Suricata loading a rule containing the 'tls.alpn' keyword, potentially indicating an attempt to exploit CVE-2026-31931.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Suricata, a network IDS, IPS, and NSM engine, is susceptible to a NULL dereference vulnerability when processing specific rule keywords. Specifically, versions 8.0.0 up to but not including 8.0.4 crash when the "tls.alpn" rule keyword is used. This vulnerability, identified as CVE-2026-31931, can be exploited to cause a denial-of-service condition, disrupting network monitoring and security operations. An attacker could craft specific network traffic or Suricata rules that trigger the flawed…
