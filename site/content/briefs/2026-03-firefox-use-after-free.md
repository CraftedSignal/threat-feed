---
title: Mozilla Firefox and Thunderbird Use-After-Free Vulnerability (CVE-2026-4688)
slug: 2026-03-firefox-use-after-free
description: A use-after-free vulnerability in the Disability Access APIs component of Mozilla Firefox and Thunderbird (CVE-2026-4688) allows for sandbox escape, potentially leading to arbitrary code execution outside the sandbox.
date: "2026-03-24T13:16:04Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - use-after-free
  - sandbox-escape
  - cve-2026-4688
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4688
  - https://bugzilla.mozilla.org/show_bug.cgi?id=2016373
  - https://www.mozilla.org/security/advisories/mfsa2026-20/
  - https://www.mozilla.org/security/advisories/mfsa2026-22/
  - https://www.mozilla.org/security/advisories/mfsa2026-23/
  - https://www.mozilla.org/security/advisories/mfsa2026-24/
rules:
  - title: Detect Firefox Crash with specific crash signature (Use-After-Free in Disability Access APIs)
    description: Detects Firefox crashes potentially related to the CVE-2026-4688 vulnerability based on crash signatures.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Thunderbird Crash with specific crash signature (Use-After-Free in Disability Access APIs)
    description: Detects Thunderbird crashes potentially related to the CVE-2026-4688 vulnerability based on crash signatures.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-4688 is a critical use-after-free vulnerability residing within the Disability Access APIs component of Mozilla Firefox and Thunderbird. Discovered and reported by Mozilla, this flaw allows for a sandbox escape, meaning an attacker could potentially execute arbitrary code outside the security sandbox normally imposed by the browser or email client. This vulnerability affects Firefox versions prior to 149, Firefox ESR (Extended Support Release) versions prior to 140.9, Thunderbird…
