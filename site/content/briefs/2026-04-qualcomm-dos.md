---
title: Qualcomm Transient Denial-of-Service via FILS Discovery Frames (CVE-2026-21367)
slug: 2026-04-qualcomm-dos
description: CVE-2026-21367 describes a transient denial-of-service vulnerability in Qualcomm products that occurs when processing nonstandard FILS Discovery Frames with out-of-range action sizes during initial scans, potentially leading to service disruption.
date: "2026-04-06T16:16:29Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - dos
  - qualcomm
  - cve-2026-21367
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1573
    technique_name: Encrypted Channel
  - tactic_id: TA0008
    tactic_name: Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
cves:
  - id: CVE-2026-21367
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-21367
  - https://docs.qualcomm.com/product/publicresources/securitybulletin/april-2026-bulletin.html
iocs:
  - type: email
    value: '[email protected]'
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 2
rules:
  - title: Detect FILS Discovery Frames with Large Action Sizes
    description: Detects network connections with potentially malicious FILS Discovery Frames based on abnormally large action sizes.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - linux
  - title: Detect Multiple FILS Discovery Frame Anomalies from Single Source
    description: Detects potential denial-of-service attacks based on a high rate of FILS Discovery Frames originating from a single source IP address.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

CVE-2026-21367 is a vulnerability affecting Qualcomm products that results in a transient denial-of-service (DoS). The vulnerability stems from the processing of nonstandard Fine Timing Measurement (FTM) Initial Link Setup (FILS) Discovery Frames which contain out-of-range action sizes during the initial network scanning phase. This issue can be triggered remotely, potentially disrupting the availability of services provided by the affected Qualcomm devices. The vulnerability was disclosed in the Qualcomm security bulletin for April 2026. Successful exploitation leads to temporary service unavailability, impacting user experience and potentially network stability.

## Attack Chain

1. An attacker crafts a malicious FILS Discovery Frame with out-of-range action sizes.
2. The attacker transmits the crafted FILS Discovery Frame to a Qualcomm device during its initial network scan.
3. The Qualcomm device receives the malicious frame and attempts to process the out-of-range action size.
4. Due to improper bounds checking, the processing of the frame triggers a buffer over-read condition (CWE-126).
5. The buffer over-read leads to a temporary system instability.
6. The device experiences a transient denial-of-service condition.
7. The affected service becomes temporarily unavailable to legitimate users.
8. After a short period, the device recovers, and the service resumes normal operation.

## Impact

Successful exploitation of CVE-2026-21367 leads to a transient denial-of-service condition on affected Qualcomm devices. The specific impact depends on the role of the device. This vulnerability has a CVSS v3.1 score of 7.6, indicating a high severity. While the DoS is transient, repeated exploitation could create a prolonged disruption, hindering user access and potentially affecting critical device functionalities.

## Recommendation

*   Monitor network traffic for malformed FILS Discovery Frames, specifically those with unusually large action sizes, using network monitoring tools (network_connection log source).
*   Apply the patches or updates provided by Qualcomm as detailed in the April 2026 security bulletin to remediate CVE-2026-21367 (reference: https://docs.qualcomm.com/product/publicresources/securitybulletin/april-2026-bulletin.html).
*   Implement rate limiting on FILS Discovery Frame processing to mitigate the impact of malicious frames (network_connection log source).
