---
title: GNU C Library iconv() Function Assertion Failure (CVE-2026-4046)
slug: 2026-03-glibc-iconv-crash
description: A vulnerability in the iconv() function of the GNU C Library (versions 2.43 and earlier) can cause a crash due to an assertion failure when handling IBM1390 or IBM1399 character sets, potentially leading to remote application denial-of-service.
date: "2026-03-30T18:16:19Z"
lastmod: "2026-07-25T15:45:17Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gnu:glibc:*:*:*:*:*:*:*:*
tags:
  - glibc
  - iconv
  - denial-of-service
  - crash
  - cve-2026-4046
vendors:
  - GNU
products:
  - The GNU C Library < 2.44
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
cves:
  - id: CVE-2026-4046
    cvss: 7.5
    epss: 0.0038
  - id: CVE-2026-4437
    cvss: 7.5
    epss: 0.00325
  - id: CVE-2026-4438
    cvss: 5.4
    epss: 0.00316
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4046
  - https://sourceware.org/bugzilla/show_bug.cgi?id=33980
  - https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=advisories/GLIBC-SA-2026-0007;hb=HEAD
  - https://seclists.org/oss-sec/2026/q3/275
rules:
  - title: Detect Iconv Crash
    description: Detects application crashes potentially caused by the iconv() vulnerability when processing IBM1390/IBM1399 character sets based on the presence of crash logs.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - application
      - linux
  - title: Detect Iconv Usage of IBM1390 or IBM1399
    description: Detects applications using the iconv() function to convert from IBM1390 or IBM1399 character sets.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - application
      - linux
rules_count: 2
updates:
  - at: "2026-07-25T15:45:17Z"
    level: L2
    summary: added CVE-2026-4046 +2; OS linux
    sources:
      - oss-security
    source_urls:
      - https://seclists.org/oss-sec/2026/q3/275
---

The GNU C Library (glibc) is a fundamental component of many Linux systems, providing core functionalities for applications. A vulnerability, CVE-2026-4046, exists within the `iconv()` function in glibc versions 2.43 and earlier. This flaw can be triggered when the library attempts to convert character sets from IBM1390 or IBM1399. If an application utilizes `iconv()` to process potentially malicious input from these character sets, it could lead to an assertion failure and subsequent crash. This vulnerability has a CVSS v3.1 score of 7.5 and may allow a remote attacker to cause a denial of service. While the vulnerability itself is within glibc, the impact is on applications which call the vulnerable function. Mitigation involves removing the vulnerable character sets from systems that do not need them.

## Attack Chain

1. An attacker crafts malicious input data using the IBM1390 or IBM1399 character sets.
2. The attacker delivers the malicious input to a vulnerable application (e.g., via a network socket, file upload, or other means).
3. The vulnerable application receives the attacker-controlled input.
4. The application calls the `iconv()` function from the GNU C Library to convert the malicious input.
5. `iconv()` attempts to convert the IBM1390 or IBM1399 input.
6. An assertion failure occurs within the `iconv()` function due to the crafted input.
7. The application process terminates abruptly due to the assertion failure.
8. The application becomes unavailable, resulting in a denial-of-service condition.

## Impact

Successful exploitation of CVE-2026-4046 can cause applications using the vulnerable `iconv()` function to crash. This can lead to a denial-of-service condition, impacting application availability and potentially disrupting business operations. The severity of the impact depends on the criticality of the affected application and the scope of its usage. Although the exact number of affected applications is unknown, any application relying on glibc's `iconv()` function for character set conversion, especially when handling external input, is potentially at risk.

## Recommendation

*   Apply the recommended mitigation of removing the IBM1390 and IBM1399 character sets from systems that do not require them. This can be done by modifying the glibc configuration files (reference: CVE-2026-4046 description).
*   Monitor application logs for crashes related to `iconv()` function calls when handling IBM1390 or IBM1399 character sets.
*   Deploy the Sigma rule `Detect Iconv Crash` to identify potential exploitation attempts based on application crash logs.
