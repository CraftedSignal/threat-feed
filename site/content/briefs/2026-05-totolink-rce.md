---
title: Totolink NR1800X Stack-Based Buffer Overflow Vulnerability
slug: 2026-05-totolink-rce
description: A stack-based buffer overflow vulnerability (CVE-2026-7546) in the Totolink NR1800X router allows remote attackers to achieve arbitrary code execution by sending a crafted HTTP request with a manipulated Host header to the vulnerable lighttpd component.
date: "2026-05-01T03:16:01Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - remote code execution
  - buffer overflow
  - router
vendors:
  - Totolink
products:
  - NR1800X 9.1.0u.6279_B20210910
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7546
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7546
  - https://github.com/newym/cve/blob/main/totolinknr1800x.md
  - https://vuldb.com/submit/804404
  - https://vuldb.com/vuln/360357
  - https://vuldb.com/vuln/360357/cti
  - https://www.totolink.net/
rules:
  - title: Detect Suspiciously Long Host Header
    description: Detects HTTP requests with unusually long Host headers, which may indicate a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect HTTP Request to lighttpd Server
    description: Detects HTTP requests specifically targeting systems running lighttpd, which may indicate attempts to exploit vulnerabilities in this web server.
    platform: sigma
    severity: informational
    tactics:
      - reconnaissance
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical security vulnerability, CVE-2026-7546, affects Totolink NR1800X routers running firmware version 9.1.0u.6279_B20210910. The vulnerability resides within the `find_host_ip` function of the lighttpd web server component. By exploiting this flaw, a remote, unauthenticated attacker can trigger a stack-based buffer overflow through manipulation of the Host argument in an HTTP request. The publicly disclosed exploit allows attackers to potentially gain complete control of the device. This vulnerability poses a significant risk to home and small business networks utilizing the affected Totolink router model, as successful exploitation leads to arbitrary code execution.

## Attack Chain

1.  The attacker identifies a vulnerable Totolink NR1800X router running firmware version 9.1.0u.6279_B20210910.
2.  The attacker crafts a malicious HTTP request targeting the router's web interface.
3.  The crafted request includes a `Host` header with a string exceeding the buffer size allocated in the `find_host_ip` function within the `lighttpd` component.
4.  The router's `lighttpd` server processes the HTTP request and passes the `Host` header value to the vulnerable function.
5.  The `find_host_ip` function attempts to store the oversized `Host` value in a stack-allocated buffer.
6.  A stack-based buffer overflow occurs due to the insufficient buffer size.
7.  The overflow overwrites adjacent memory on the stack, potentially including the return address.
8.  The attacker gains arbitrary code execution on the device.

## Impact

Successful exploitation of CVE-2026-7546 allows a remote attacker to execute arbitrary code on the vulnerable Totolink NR1800X device. This can lead to complete control of the router, allowing the attacker to modify router settings, intercept network traffic, or use the compromised router as a pivot point for further attacks within the network. Given the nature of stack-based buffer overflows, the attacker can potentially install persistent backdoors or malware. This presents a significant risk to users, potentially exposing sensitive data and infrastructure to unauthorized access.

## Recommendation

*   Apply available patches released by Totolink to remediate CVE-2026-7546.
*   Monitor network traffic for suspicious HTTP requests targeting Totolink routers, specifically looking for abnormally long Host headers with the Sigma rule "Detect Suspiciously Long Host Header".
*   Implement network segmentation to limit the impact of a compromised router.
*   Review and harden router configurations, including disabling remote administration if not required.
