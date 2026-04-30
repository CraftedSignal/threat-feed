---
title: CPCI85 and SICORE Base System XML Out-of-Bounds Write Vulnerability
slug: 2026-03-cpc85-xml-dos
description: An unauthenticated attacker can exploit an out-of-bounds write vulnerability in CPCI85 Central Processing/Communication and SICORE Base System by sending a malicious XML request, potentially causing a service crash leading to a denial-of-service condition.
date: "2026-03-26T15:16:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-27664
  - denial-of-service
  - xml
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27664
  - https://cert-portal.siemens.com/productcert/html/ssa-246443.html
rules:
  - title: Detect Suspicious XML Request Patterns
    description: Detects potentially malicious XML requests based on content patterns that may indicate exploit attempts.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - linux
  - title: Detect Service Crashes from XML Processing
    description: Detects service crashes potentially resulting from malicious XML processing based on process termination events.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A vulnerability, tracked as CVE-2026-27664, exists within CPCI85 Central Processing/Communication (all versions prior to V26.10) and SICORE Base system (all versions prior to V26.10.0). This flaw stems from an out-of-bounds write during the parsing of maliciously crafted XML inputs. An unauthenticated attacker could exploit this vulnerability by sending a specifically designed XML request to the targeted system. Successful exploitation results in a service crash, effectively creating a denial-of-service (DoS) condition. This vulnerability poses a significant risk to the availability of systems relying on the affected CPCI85 and SICORE Base system components. Defenders should prioritize patching and implement mitigations to prevent potential disruptions.

## Attack Chain

1.  The attacker identifies a vulnerable CPCI85 or SICORE Base system instance exposed to network traffic.
2.  The attacker crafts a malicious XML payload designed to trigger the out-of-bounds write vulnerability.
3.  The attacker sends the malicious XML payload to the targeted system via a network request.
4.  The CPCI85 or SICORE Base system receives the XML payload and attempts to parse it.
5.  During XML parsing, the vulnerability is triggered due to the specially crafted XML structure, leading to an out-of-bounds write operation.
6.  The out-of-bounds write corrupts memory within the application process.
7.  The memory corruption causes the service to crash.
8.  The crash results in a denial-of-service condition, rendering the affected system unavailable.

## Impact

Successful exploitation of CVE-2026-27664 leads to a denial-of-service condition on the affected CPCI85 Central Processing/Communication and SICORE Base systems. The number of potential victims depends on the deployment scope of these systems; however, any system using versions prior to V26.10 and V26.10.0, respectively, is vulnerable. This DoS can disrupt critical operations relying on these systems, potentially impacting industrial control processes or other essential services.

## Recommendation

*   Apply the security patch provided by Siemens to update CPCI85 Central Processing/Communication to version V26.10 or later, and SICORE Base system to version V26.10.0 or later to remediate CVE-2026-27664 (https://cert-portal.siemens.com/productcert/html/ssa-246443.html).
*   Implement network segmentation and access control policies to limit exposure of CPCI85 and SICORE Base systems to untrusted networks.
*   Monitor web server logs for abnormal XML request patterns targeting the affected systems using a custom rule inspecting `cs-uri-query` for anomalous XML structures.
