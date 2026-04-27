---
title: util-linux Vulnerability Allows DoS and Information Disclosure
slug: 2024-04-util-linux-dos-info-disclosure
description: A local attacker can exploit a vulnerability in util-linux to perform a denial of service attack and disclose sensitive information.
date: "2026-04-22T08:08:57Z"
severities:
  - medium
tags:
  - util-linux
  - denial-of-service
  - information-disclosure
  - linux
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Information Discovery
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-2755
rules:
  - title: Detect Suspicious util-linux Utility Execution
    description: Detects unusual execution of common util-linux utilities that might indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
      - discovery
    techniques:
      - T1068
      - T1499.001
    data_sources:
      - process_creation
      - linux
  - title: Detect abnormal fdisk usage
    description: Detects suspicious use of fdisk that may indicate unauthorized disk modifications.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1078
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A vulnerability exists within the util-linux package that can be exploited by a local attacker. While specific details regarding the vulnerable component or version are not provided in the advisory, successful exploitation can lead to a denial-of-service (DoS) condition and the disclosure of sensitive information. The impact is limited to systems where the attacker has local access, but successful exploitation could disrupt services and expose sensitive data to unauthorized users. Defenders…
