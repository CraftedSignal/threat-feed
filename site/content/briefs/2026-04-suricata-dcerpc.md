---
title: Suricata DCERPC Buffering Inefficiency Vulnerability (CVE-2026-31937)
slug: 2026-04-suricata-dcerpc
description: Suricata versions prior to 7.0.15 are vulnerable to CVE-2026-31937, where inefficient DCERPC buffering can lead to a denial-of-service condition through performance degradation.
date: "2026-04-02T15:16:37Z"
severities:
  - medium
tags:
  - vulnerability
  - dos
  - suricata
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
cves:
  - id: CVE-2026-31937
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-31937
  - https://github.com/OISF/suricata/security/advisories/GHSA-86vg-w8vm-m3gg
  - https://redmine.openinfosecfoundation.org/issues/8304
ioc_counts:
  email: 1
rules:
  - title: Detect High Volume of DCERPC Traffic
    description: Detects a high volume of DCERPC traffic which may indicate a DoS attack against Suricata.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - suricata
  - title: Detect DCERPC Traffic to Unusual Ports
    description: Detects DCERPC traffic on non-standard ports, which could indicate malicious activity.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.002
    data_sources:
      - network_connection
      - suricata
rules_count: 2
---

CVE-2026-31937 describes a vulnerability in Suricata, a network IDS/IPS/NSM engine. Prior to version 7.0.15, Suricata suffers from inefficiency in its DCERPC buffering mechanism. This inefficiency can be exploited by a malicious actor to cause a performance degradation, potentially leading to a denial-of-service (DoS) condition. The vulnerability was reported on April 2, 2026, and patched in Suricata version 7.0.15. The vulnerability has a CVSS v3.1 score of 7.5 (High). Successful exploitation…
