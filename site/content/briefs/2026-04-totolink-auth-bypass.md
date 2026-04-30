---
title: Totolink A8000R Authentication Bypass Vulnerability (CVE-2026-5676)
slug: 2026-04-totolink-auth-bypass
description: A remote, unauthenticated attacker can bypass authentication on Totolink A8000R routers running firmware version 5.9c.681_B20180413 by manipulating the `langType` argument in the `setLanguageCfg` function of the `/cgi-bin/cstecgi.cgi` file.
date: "2026-04-06T19:16:30Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-5676
  - authentication-bypass
  - totolink
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5676
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5676
  - https://github.com/skeetabc/CVE-TOTOLINK-A800R/blob/main/vuln1_auth_bypass.md
  - https://vuldb.com/vuln/355503
rules:
  - title: Detect Totolink A8000R Authentication Bypass Attempt
    description: Detects attempts to exploit the authentication bypass vulnerability (CVE-2026-5676) in Totolink A8000R routers by monitoring HTTP requests to the vulnerable cgi file.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Totolink A8000R Set Language Exploit Attempt
    description: Detects potential exploitation attempts against the Totolink A8000R router by monitoring web requests to the cstecgi.cgi endpoint with suspicious langType parameters.
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

CVE-2026-5676 is an authentication bypass vulnerability affecting Totolink A8000R routers with firmware version 5.9c.681_B20180413. The vulnerability resides in the `/cgi-bin/cstecgi.cgi` file, specifically within the `setLanguageCfg` function. By manipulating the `langType` argument, an attacker can bypass authentication checks, potentially gaining unauthorized access to sensitive router functionalities. This vulnerability can be exploited remotely without requiring any prior authentication. A public exploit is available, increasing the likelihood of exploitation. Defenders should prioritize detection and patching of this vulnerability to prevent unauthorized access and control of affected devices.

## Attack Chain

1. An attacker identifies a vulnerable Totolink A8000R router running firmware 5.9c.681_B20180413.
2. The attacker sends a crafted HTTP request to `/cgi-bin/cstecgi.cgi`.
3. The request targets the `setLanguageCfg` function.
4. The request includes a manipulated `langType` argument designed to bypass authentication.
5. The vulnerable `setLanguageCfg` function processes the request without proper authentication checks.
6. The attacker gains unauthorized access to router configuration settings.
7. The attacker modifies sensitive settings such as DNS, routing rules, or firewall configuration.
8. The attacker achieves full control of the router, potentially using it for malicious purposes like eavesdropping, traffic redirection, or botnet activities.

## Impact

Successful exploitation of CVE-2026-5676 allows a remote, unauthenticated attacker to gain full control of the affected Totolink A8000R router. This can lead to a variety of malicious activities, including unauthorized access to the local network, data theft, DNS hijacking, and the use of the router as part of a botnet. The potential number of affected devices is substantial, as the A8000R model is widely used.

## Recommendation

*   Deploy the Sigma rule to detect malicious HTTP requests targeting the vulnerable `setLanguageCfg` function (see "Detect Totolink A8000R Authentication Bypass Attempt" rule below).
*   Monitor web server logs for requests to `/cgi-bin/cstecgi.cgi` with unusual `langType` parameters (see "Detect Totolink A8000R Authentication Bypass Attempt" rule below).
*   Upgrade the firmware of Totolink A8000R routers to a patched version that addresses CVE-2026-5676 (consult the vendor's website for updates).
*   Implement network segmentation to limit the impact of a compromised router on other devices on the network.
