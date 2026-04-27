---
title: CVE-2026-31622 NFC-A Cascade Depth Bounds Check Failure
slug: 2024-05-nfc-bounds-check-failure
description: CVE-2026-31622 describes a vulnerability related to an NFC bounds check issue, specifically a failure to properly validate NFC-A cascade depth in the SDD response handler within Microsoft products, potentially leading to unexpected behavior or security compromise.
date: "2026-04-26T07:28:13Z"
severities:
  - medium
tags:
  - nfc
  - bounds-check-failure
  - cve-2026-31622
vendors:
  - Microsoft
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Exploit
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-31622
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-31622
rules:
  - title: Detect Suspicious NFC Activity
    description: Detects potential exploitation attempts related to unusual NFC activity
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - windows
  - title: Detect High Volume NFC Traffic
    description: Detects potential denial of service attempts via high volume NFC traffic
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-31622 involves a failure to perform adequate bounds checking of the NFC-A cascade depth in the SDD response handler. This vulnerability within Microsoft's NFC component could be exploited by a specially crafted NFC transmission that provides an unexpected cascade depth value, potentially leading to a denial-of-service condition or other unspecified impact. Due to the nature of NFC vulnerabilities, an attacker needs to be in close physical proximity to the targeted device. The…
