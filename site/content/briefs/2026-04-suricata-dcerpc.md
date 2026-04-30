---
title: Suricata DCERPC Buffering Inefficiency Vulnerability (CVE-2026-31937)
slug: 2026-04-suricata-dcerpc
description: Suricata versions prior to 7.0.15 are vulnerable to CVE-2026-31937, where inefficient DCERPC buffering can lead to a denial-of-service condition through performance degradation.
date: "2026-04-02T15:16:37Z"
severities:
  - medium
type: advisory
types:
  - advisory
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
iocs:
  - type: email
    value: '[email protected]'
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

CVE-2026-31937 describes a vulnerability in Suricata, a network IDS/IPS/NSM engine. Prior to version 7.0.15, Suricata suffers from inefficiency in its DCERPC buffering mechanism. This inefficiency can be exploited by a malicious actor to cause a performance degradation, potentially leading to a denial-of-service (DoS) condition. The vulnerability was reported on April 2, 2026, and patched in Suricata version 7.0.15. The vulnerability has a CVSS v3.1 score of 7.5 (High). Successful exploitation requires no privileges and no user interaction, making it easily exploitable. Organizations using affected versions of Suricata should upgrade to version 7.0.15 or later.

## Attack Chain

1.  Attacker identifies a Suricata instance running a version prior to 7.0.15.
2.  Attacker crafts a series of network packets containing specially formatted DCERPC requests.
3.  The crafted DCERPC requests are sent to the targeted Suricata instance.
4.  Suricata receives the malformed DCERPC requests.
5.  Due to the DCERPC buffering inefficiency (CWE-407), Suricata's processing resources are exhausted.
6.  Suricata's performance degrades significantly as it struggles to handle the influx of inefficient DCERPC requests.
7.  Legitimate network traffic monitoring and protection capabilities are impaired due to resource exhaustion.
8.  Continued exploitation leads to a denial-of-service condition, preventing Suricata from properly analyzing network traffic.

## Impact

Successful exploitation of CVE-2026-31937 results in performance degradation of the Suricata network IDS/IPS/NSM engine. This can lead to a denial-of-service (DoS) condition, preventing Suricata from effectively monitoring network traffic. While the source does not specify the number of affected organizations, any organization using Suricata versions prior to 7.0.15 is potentially vulnerable. The impact can range from temporary performance issues to complete failure of network security monitoring capabilities.

## Recommendation

*   Upgrade Suricata installations to version 7.0.15 or later to remediate the vulnerability (CVE-2026-31937).
*   Monitor network traffic for unusual patterns of DCERPC requests targeting Suricata instances using the provided Sigma rule.
*   Implement rate limiting or traffic shaping rules to mitigate the impact of excessive DCERPC traffic, particularly from unknown or untrusted sources, as detailed in the overview.
