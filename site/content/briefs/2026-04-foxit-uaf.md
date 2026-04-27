---
title: Foxit Application Use-After-Free Vulnerability (CVE-2026-3779)
slug: 2026-04-foxit-uaf
description: CVE-2026-3779 is a use-after-free vulnerability in a Foxit application where stale references to page/form objects can lead to arbitrary code execution via crafted documents.
date: "2026-04-01T02:16:03Z"
severities:
  - high
tags:
  - cve-2026-3779
  - use-after-free
  - code-execution
  - foxit
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-3779
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3779
  - https://www.foxit.com/support/security-bulletins.html
rules:
  - title: Suspicious Child Process of Foxit Application
    description: Detects suspicious child processes spawned by the Foxit application, potentially indicating exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Foxit Application launching mshta.exe
    description: Detects mshta.exe being launched by a Foxit application, which is often a sign of exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1218.005
      - T1566.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-3779 is a use-after-free vulnerability affecting an unspecified Foxit application. The vulnerability stems from the application's list box calculate array logic, which improperly manages references to page or form objects. Specifically, when these objects are deleted or re-created, the calculation logic retains stale references. This flaw allows attackers to craft malicious documents that, upon calculation, trigger a use-after-free condition. Successful exploitation of this…
