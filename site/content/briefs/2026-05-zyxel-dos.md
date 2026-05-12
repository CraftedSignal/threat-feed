---
title: CVE-2026-7287 - Zyxel NWA1100-N Buffer Overflow Vulnerability
slug: 2026-05-zyxel-dos
description: A buffer overflow vulnerability in Zyxel NWA1100-N firmware allows a remote attacker to cause a denial-of-service by sending a crafted HTTP request to the webs binary.
date: "2026-05-12T04:18:29Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - dos
  - buffer overflow
  - cve-2026-7287
vendors:
  - Zyxel
products:
  - NWA1100-N customized firmware
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.001
    technique_name: 'Endpoint Denial of Service: Application Exhaustion'
cves:
  - id: CVE-2026-7287
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7287
  - https://www.zyxel.com/global/en/support/end-of-life
rules:
  - title: Detect CVE-2026-7287 Exploitation Attempt — Crafted HTTP Request
    description: Detects attempts to exploit CVE-2026-7287 by identifying suspicious HTTP requests targeting vulnerable functions in the Zyxel NWA1100-N web interface.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
  - title: Detect CVE-2026-7287 Exploitation Attempt — Long HTTP Parameter
    description: Detects attempts to exploit CVE-2026-7287 by identifying overly long HTTP GET parameters.
    platform: sigma
    severity: low
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
rules_count: 2
---

CVE-2026-7287 describes a buffer overflow vulnerability affecting Zyxel NWA1100-N devices running customized firmware version 1.00(AACE.1)C0. The vulnerability exists within the “webs” binary, specifically in the formWep(), formWlAc(), formPasswordSetup(), formUpgradeCert(), and formDelcert() functions. An attacker can exploit this flaw by sending a specially crafted HTTP request to the targeted device. Successful exploitation leads to a denial-of-service (DoS) condition, rendering the device unavailable. This vulnerability is classified as unsupported when assigned, indicating potential limitations in vendor support or remediation.

## Attack Chain

1.  Attacker identifies a vulnerable Zyxel NWA1100-N device running firmware version 1.00(AACE.1)C0.
2.  Attacker crafts a malicious HTTP request targeting the "webs" binary.
3.  The HTTP request is designed to trigger a buffer overflow in one of the vulnerable functions: formWep(), formWlAc(), formPasswordSetup(), formUpgradeCert(), or formDelcert().
4.  The device processes the crafted HTTP request.
5.  The vulnerable function attempts to write data beyond the allocated buffer.
6.  The buffer overflow corrupts memory, leading to a crash or unexpected behavior within the "webs" process.
7.  The "webs" process becomes unresponsive, causing a denial of service.

## Impact

Successful exploitation of CVE-2026-7287 results in a denial-of-service (DoS) condition on the affected Zyxel NWA1100-N device. This means the device becomes unavailable to legitimate users, disrupting network connectivity and potentially impacting business operations. The NVD assigns this vulnerability a CVSS v3.1 base score of 7.5, indicating a high potential impact in terms of availability.

## Recommendation

*   Monitor web server logs for unusual HTTP requests targeting the vulnerable functions (`formWep`, `formWlAc`, `formPasswordSetup`, `formUpgradeCert`, `formDelcert`) on Zyxel devices, using a rule similar to the example below.
*   Consult the Zyxel end-of-life page referenced for potential mitigation strategies or device replacement options.
*   Since this CVE is marked as "unsupported when assigned", consider network segmentation to limit the impact of a successful exploit if device replacement or patching is not possible.
