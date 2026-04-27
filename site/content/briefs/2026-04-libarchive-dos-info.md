---
title: libarchive Multiple Vulnerabilities Allow Information Disclosure and DoS
slug: 2026-04-libarchive-dos-info
description: Multiple vulnerabilities in libarchive can be exploited by a remote attacker to disclose information or cause a denial-of-service condition.
date: "2026-04-21T08:04:42Z"
severities:
  - medium
tags:
  - vulnerability
  - denial-of-service
  - information-disclosure
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
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0803
rules:
  - title: Detect Suspicious Child Process of Archive Handling Application
    description: Detects suspicious child processes spawned by applications that handle archive files, potentially indicating exploitation.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1569.002
    data_sources:
      - process_creation
      - windows
  - title: Detect High Resource Usage by Archive Handling Process
    description: Detects processes known to handle archive files exhibiting unusually high CPU or memory usage, potentially indicating a denial-of-service attack.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Multiple vulnerabilities exist within the libarchive library that can be exploited by a remote, anonymous attacker. These vulnerabilities could lead to both information disclosure and denial-of-service (DoS) conditions. The lack of specific version information or CVEs makes targeted patching and detection challenging. Defenders should focus on generic indicators related to abnormal process behavior when handling archive files. While the advisory lacks detailed technical information, the broad…
