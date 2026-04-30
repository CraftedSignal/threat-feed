---
title: GNU C Library iconv() Function Assertion Failure (CVE-2026-4046)
slug: 2026-03-glibc-iconv-crash
description: A vulnerability in the iconv() function of the GNU C Library (versions 2.43 and earlier) can cause a crash due to an assertion failure when handling IBM1390 or IBM1399 character sets, potentially leading to remote application denial-of-service.
date: "2026-03-30T18:16:19Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - glibc
  - iconv
  - denial-of-service
  - crash
  - cve-2026-4046
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4046
  - https://sourceware.org/bugzilla/show_bug.cgi?id=33980
  - https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=advisories/GLIBC-SA-2026-0007;hb=HEAD
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
---

The GNU C Library (glibc) is a fundamental component of many Linux systems, providing core functionalities for applications. A vulnerability, CVE-2026-4046, exists within the `iconv()` function in glibc versions 2.43 and earlier. This flaw can be triggered when the library attempts to convert character sets from IBM1390 or IBM1399. If an application utilizes `iconv()` to process potentially malicious input from these character sets, it could lead to an assertion failure and subsequent crash…
