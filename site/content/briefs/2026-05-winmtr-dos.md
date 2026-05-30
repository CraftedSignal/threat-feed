---
title: WinMTR 0.91 Denial of Service Vulnerability (CVE-2018-25426)
slug: 2026-05-winmtr-dos
description: WinMTR 0.91 is vulnerable to a denial-of-service attack where a malformed payload file containing a buffer overflow can crash the application (CVE-2018-25426).
date: "2026-05-30T16:21:49Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - dos
  - buffer overflow
  - cve-2018-25426
vendors:
  - WinMTR
products:
  - WinMTR 0.91
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2018-25426
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25426
  - http://winmtr.net
  - http://winmtr.net/winmtr_download/
  - https://www.exploit-db.com/exploits/45769
  - https://www.vulncheck.com/advisories/winmtr-denial-of-service-via-buffer-overflow
rules:
  - title: File Open with WinMTR
    description: Detects suspicious file opens with WinMTR that might lead to a crash due to CVE-2018-25426
    platform: sigma
    severity: low
    tactics:
      - availability
      - denial_of_service
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

WinMTR version 0.91 is susceptible to a denial-of-service vulnerability. This flaw can be exploited by crafting a malformed payload file with a large buffer of repeated characters. When the vulnerable application processes this crafted file, it leads to a buffer overflow, causing the application to crash. The attacker can create a specially crafted input file with 238 bytes of data to trigger this buffer overflow condition. Exploitation of this vulnerability requires no authentication and can be triggered remotely, making it a significant concern for systems running WinMTR.

## Attack Chain

1. Attacker crafts a malicious input file containing a buffer of 238 repeated characters.
2. The malicious file is delivered to the target system. The delivery method is not specified in the source.
3. WinMTR 0.91 attempts to open and process the malicious file.
4. Due to the oversized buffer, a buffer overflow occurs within the WinMTR application.
5. The buffer overflow corrupts memory, leading to unpredictable behavior.
6. WinMTR 0.91 crashes due to the memory corruption caused by the buffer overflow.
7. The application becomes unavailable, resulting in a denial-of-service condition.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition, rendering WinMTR 0.91 unusable. While the number of victims and targeted sectors are unspecified, any system running the vulnerable version of WinMTR is at risk. A successful attack would disrupt network monitoring activities relying on this tool.

## Recommendation

*   Monitor for attempts to open unusual or malformed files with WinMTR using the `File Open with WinMTR` Sigma rule to detect potential exploitation attempts.
*   Apply any available patches or upgrades provided by WinMTR to remediate CVE-2018-25426.
*   Consider using alternative network monitoring tools that are not vulnerable to buffer overflow attacks.
