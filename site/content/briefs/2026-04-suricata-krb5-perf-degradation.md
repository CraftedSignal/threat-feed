---
title: Suricata KRB5 Buffering Inefficiency Vulnerability (CVE-2026-31932)
slug: 2026-04-suricata-krb5-perf-degradation
description: An unauthenticated attacker can exploit CVE-2026-31932, a vulnerability in Suricata versions prior to 7.0.15 and 8.0.4, to cause performance degradation due to inefficient KRB5 buffering.
date: "2026-04-02T14:16:28Z"
severities:
  - medium
tags:
  - cve-2026-31932
  - suricata
  - krb5
  - performance-degradation
  - denial-of-service
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-31932
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-31932
  - https://github.com/OISF/suricata/security/advisories/GHSA-rp9m-jcpw-hggr
  - https://redmine.openinfosecfoundation.org/issues/8305
ioc_counts:
  email: 1
rules:
  - title: Detect High KRB5 Traffic Volume
    description: Detects a high volume of KRB5 network traffic, which may indicate an attempt to exploit CVE-2026-31932 against Suricata.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - suricata
  - title: Detect Suricata Performance Degradation (High CPU Usage)
    description: Detects potential exploitation of CVE-2026-31932 by monitoring Suricata's CPU usage. Triggered when CPU usage exceeds a defined threshold.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-31932 is a vulnerability affecting Suricata, a widely used network intrusion detection and prevention system (IDS/IPS) and network security monitoring (NSM) engine. The vulnerability stems from an inefficiency in how Suricata handles KRB5 buffering.  Successful exploitation of this vulnerability can lead to a noticeable performance degradation of the Suricata engine. The vulnerability is present in Suricata versions prior to 7.0.15 and 8.0.4. Organizations using affected versions of…
