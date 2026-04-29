---
title: CVE-2026-31622 NFC-A Cascade Depth Bounds Check Failure
slug: 2024-05-nfc-bounds-check-failure
description: CVE-2026-31622 describes a vulnerability related to an NFC bounds check issue, specifically a failure to properly validate NFC-A cascade depth in the SDD response handler within Microsoft products, potentially leading to unexpected behavior or security compromise.
date: "2026-04-26T07:28:13Z"
type: coverage
types:
  - coverage
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

CVE-2026-31622 involves a failure to perform adequate bounds checking of the NFC-A cascade depth in the SDD response handler. This vulnerability within Microsoft's NFC component could be exploited by a specially crafted NFC transmission that provides an unexpected cascade depth value, potentially leading to a denial-of-service condition or other unspecified impact. Due to the nature of NFC vulnerabilities, an attacker needs to be in close physical proximity to the targeted device. The vulnerability was reported publicly and assigned a CVE in April 2026. Defenders should prioritize applying relevant patches from Microsoft to mitigate potential exploitation attempts.

## Attack Chain

1.  Attacker positions themselves within NFC communication range of the target device.
2.  Attacker initiates an NFC communication session with the target device.
3.  Attacker sends an NFC-A SDD (Single Device Detection) request.
4.  The target device's NFC controller begins processing the SDD request.
5.  Attacker crafts a malicious SDD response with an invalid cascade depth.
6.  The NFC controller fails to properly validate the cascade depth value.
7.  The improper cascade depth value leads to a buffer overflow or out-of-bounds read.
8.  The vulnerability is triggered, potentially resulting in a denial-of-service or other unspecified impact.

## Impact

Successful exploitation of CVE-2026-31622 could lead to a denial-of-service condition on the targeted device. While the specific consequences are not detailed, this type of vulnerability could potentially be leveraged for more severe impacts. Given the proximity requirement for NFC attacks, the risk is somewhat mitigated.

## Recommendation

*   Monitor systems for unexpected NFC activity, focusing on devices that frequently interact with NFC transmissions.
*   Apply the security update released by Microsoft to patch CVE-2026-31622 once available.
*   Implement network segmentation to limit the impact of potential exploits originating from compromised devices utilizing NFC.
*   Deploy the Sigma rules below to detect potential exploitation attempts related to unusual NFC activity.
