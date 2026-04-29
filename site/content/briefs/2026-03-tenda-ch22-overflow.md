---
title: Tenda CH22 Router Stack-Based Buffer Overflow Vulnerability
slug: 2026-03-tenda-ch22-overflow
description: A stack-based buffer overflow vulnerability exists in Tenda CH22 1.0.0.1 via manipulation of the `mit_linktype` argument in the `/goform/QuickIndex` endpoint, potentially enabling remote code execution.
date: "2026-03-31T00:16:15Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - cve-2026-5156
  - buffer-overflow
  - tenda
  - router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5156
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5156
  - https://github.com/Litengzheng/vuldb_new/blob/main/CH22/vul_46/README.md
  - https://vuldb.com/vuln/354188
rules:
  - title: Detect Tenda CH22 mit_linktype Buffer Overflow Attempt
    description: Detects potential buffer overflow attempts on Tenda CH22 routers by monitoring the length of the `mit_linktype` parameter in POST requests to `/goform/QuickIndex`.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda CH22 Exploitation Attempt via HTTP Request
    description: Detects a potential exploitation attempt against Tenda CH22 routers by looking for a specific URI and request method combination.
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

A stack-based buffer overflow vulnerability has been identified in Tenda CH22 router version 1.0.0.1. The vulnerability resides within the `formQuickIndex` function of the `/goform/QuickIndex` file, which is a component of the Parameter Handler. This flaw can be triggered by manipulating the `mit_linktype` argument, leading to a buffer overflow on the stack. The vulnerability is remotely exploitable, meaning an attacker can trigger the flaw over the network without needing local access to the device. The existence of a public exploit further increases the risk of potential exploitation by malicious actors. Successful exploitation could allow an attacker to execute arbitrary code on the device.

## Attack Chain

1. An attacker identifies a vulnerable Tenda CH22 router running firmware version 1.0.0.1 exposed to the internet.
2. The attacker crafts a malicious HTTP POST request targeting the `/goform/QuickIndex` endpoint.
3. The malicious request includes the `mit_linktype` argument with a payload exceeding the expected buffer size.
4. The Tenda CH22 router processes the HTTP request and passes the `mit_linktype` argument to the `formQuickIndex` function.
5. The `formQuickIndex` function copies the attacker-controlled `mit_linktype` data into a fixed-size buffer on the stack without proper bounds checking.
6. Due to the oversized payload, the copy operation overflows the buffer, overwriting adjacent memory on the stack, including the return address.
7. The `formQuickIndex` function completes and attempts to return to the caller function.
8. Due to the overwritten return address, control is redirected to attacker-controlled code, enabling arbitrary code execution.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code on the Tenda CH22 router. This can lead to a variety of malicious outcomes, including complete device compromise, denial of service, and the potential to use the router as a launchpad for further attacks on the local network or the internet. Given that routers are often used in both home and small business environments, a successful attack could affect a wide range of users and organizations.

## Recommendation

*   Monitor web server logs for POST requests to `/goform/QuickIndex` with unusually long `mit_linktype` parameters to detect potential exploitation attempts. Implement the Sigma rule `Detect Tenda CH22 mit_linktype Buffer Overflow Attempt` against web server logs.
*   Implement rate limiting on the `/goform/QuickIndex` endpoint to mitigate potential denial-of-service attacks stemming from exploitation.
*   Since the source material identifies CWE-119 and CWE-121 as root causes, review code practices related to buffer handling and implement stricter input validation procedures.
