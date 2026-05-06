---
title: Tenda FH1201 Stack-Based Buffer Overflow Vulnerability (CVE-2026-5046)
slug: 2026-03-tenda-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-5046) in Tenda FH1201 version 1.2.0.14(408) allows remote attackers to execute arbitrary code by manipulating the GO argument in the formWrlExtraSet function of the /goform/WrlExtraSet component.
date: "2026-03-29T15:16:36Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - CVE-2026-5046
  - tenda
  - buffer-overflow
  - router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5046
  - https://github.com/Litengzheng/vul_db/blob/main/FH1201/vul_44/README.md
  - https://vuldb.com/vuln/353969
rules:
  - title: Detect Suspiciously Long GO Parameter in Tenda FH1201 Request
    description: Detects HTTP POST requests to /goform/WrlExtraSet with a GO parameter exceeding a reasonable length, indicating a potential buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda FH1201 formWrlExtraSet Access from Unusual IP
    description: Detects access to the formWrlExtraSet endpoint from IP addresses not commonly associated with router administration, potentially indicating unauthorized access or exploitation attempts.
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

CVE-2026-5046 is a stack-based buffer overflow vulnerability affecting Tenda FH1201 routers running firmware version 1.2.0.14(408). The vulnerability resides within the `formWrlExtraSet` function of the `/goform/WrlExtraSet` component, specifically in the handling of the `GO` argument. A remote attacker can exploit this flaw by sending a crafted HTTP request with a maliciously oversized `GO` parameter, overwriting the stack and potentially gaining arbitrary code execution on the device. The…
