---
title: Suricata NULL Dereference Vulnerability
slug: 2026-04-suricata-null-dereference
description: Suricata versions 8.0.0 to before 8.0.4 are vulnerable to a NULL dereference crash when using the 'tls.alpn' rule keyword, potentially leading to a denial of service.
date: "2026-04-02T14:16:28Z"
type: coverage
types:
  - coverage
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
iocs:
  - type: email
    value: '[email protected]'
  - type: email
    value: '[email protected]'
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

Suricata, a network IDS, IPS, and NSM engine, is susceptible to a NULL dereference vulnerability when processing specific rule keywords. Specifically, versions 8.0.0 up to but not including 8.0.4 crash when the "tls.alpn" rule keyword is used. This vulnerability, identified as CVE-2026-31931, can be exploited to cause a denial-of-service condition, disrupting network monitoring and security operations. An attacker could craft specific network traffic or Suricata rules that trigger the flawed code path, causing the Suricata process to terminate. The vulnerability has been patched in Suricata version 8.0.4.

## Attack Chain

1. An attacker identifies a Suricata instance running a vulnerable version (8.0.0 - 8.0.3).
2. The attacker crafts a Suricata rule containing the `tls.alpn` keyword.
3. The attacker deploys the crafted rule to the Suricata instance, either directly or via a configuration management system.
4. Suricata attempts to load and process the rule, triggering the vulnerable code path in the `tls.alpn` processing function.
5. The vulnerable code dereferences a NULL pointer, leading to a segmentation fault.
6. The Suricata process crashes, terminating network intrusion detection and prevention capabilities.
7. The attacker may repeat this process to ensure continued disruption.

## Impact

Successful exploitation of CVE-2026-31931 results in a denial-of-service condition affecting the Suricata network security engine.  This can lead to blind spots in network monitoring, allowing malicious traffic to pass undetected. The number of affected installations depends on the adoption rate of Suricata versions 8.0.0 through 8.0.3 across various organizations and sectors. Critical network infrastructure, security operations centers, and organizations relying on Suricata for threat detection are potentially impacted.

## Recommendation

*   Upgrade Suricata installations to version 8.0.4 or later to remediate CVE-2026-31931 ([https://github.com/OISF/suricata/security/advisories/GHSA-gr22-4784-xvw3](https://github.com/OISF/suricata/security/advisories/GHSA-gr22-4784-xvw3)).
*   Implement rate limiting or input validation on Suricata rule deployments to prevent malicious rule injection.
*   Monitor Suricata process stability and restart automatically if crashes are detected, to mitigate the impact of the vulnerability (syslog, process monitoring).
