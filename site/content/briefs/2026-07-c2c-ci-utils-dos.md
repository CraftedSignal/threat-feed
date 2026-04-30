---
title: C2C CI utils Vulnerable to DoS via pyasn Dependency (CVE-2026-30922)
slug: 2026-07-c2c-ci-utils-dos
description: The c2cciutils package is vulnerable to denial of service due to an uncontrolled recursion vulnerability (CWE-674) in the pyasn dependency, specifically versions before 1.1.65.
date: "2026-03-26T22:27:55Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - denial-of-service
  - pyasn
  - c2cciutils
  - dependency-vulnerability
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-wcjx-v2wj-xg87
  - https://github.com/advisories/GHSA-jr27-m4p2-rc6r
rules:
  - title: Detect High CPU Usage by Python Processes
    description: Detects a python process consuming unusually high CPU, which could be a sign of DoS via uncontrolled recursion.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
  - title: Detect High Memory Usage by Python Processes
    description: Detects a python process consuming unusually high memory, which could be a sign of DoS via uncontrolled recursion.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The c2cciutils package, a CI utility, is susceptible to a denial-of-service (DoS) attack due to an uncontrolled recursion vulnerability within its pyasn dependency. Specifically, versions of c2cciutils prior to 1.1.65 are affected. This vulnerability, identified as CVE-2026-30922, stems from a flaw in the pyasn library (see GHSA-jr27-m4p2-rc6r) which leads to excessive resource consumption when processing certain inputs. An attacker can exploit this flaw remotely with low complexity, no…
