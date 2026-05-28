---
title: 'CVE-2026-46099: IPv6 NOREF DST Use Vulnerability in seg6 and rpl lwtunnels'
slug: 2026-05-ipv6-noref-dst
description: CVE-2026-46099 describes a vulnerability in the IPv6 network stack related to NOREF dst use in seg6 and rpl lwtunnels, requiring a security update to address potential exploitation.
date: "2026-05-28T07:29:39Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ipv6
  - network
  - denial-of-service
  - information-disclosure
vendors:
  - Microsoft
cves:
  - id: CVE-2026-46099
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-46099
rules:
  - title: Detect Suspicious IPv6 Traffic - seg6
    description: Detects suspicious IPv6 traffic potentially exploiting issues in seg6 handling (CVE-2026-46099).
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - network_connection
      - windows
  - title: Detect Suspicious IPv6 Traffic - rpl lwtunnels
    description: Detects suspicious IPv6 traffic potentially exploiting issues in rpl lwtunnels handling (CVE-2026-46099).
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-46099 is a security vulnerability impacting the IPv6 implementation within the network component. The vulnerability stems from improper handling of NOREF destination entries in the seg6 (segment routing IPv6) and rpl (Routing Protocol for Low-Power and Lossy Networks) lwtunnels (lightweight tunnels) functionalities. This could potentially lead to unexpected behavior or security issues within the network stack. A security update has been released to address this vulnerability. Defenders should apply the patch to mitigate any risks associated with this flaw. The scope of the vulnerability is limited to systems utilizing the affected IPv6 functionalities.

## Attack Chain

Due to the limited information available, a detailed attack chain cannot be constructed. However, a potential exploitation scenario could involve the following steps:

1. An attacker crafts a malicious IPv6 packet utilizing seg6 or rpl lwtunnels.
2. The crafted packet triggers the improper handling of NOREF destination entries.
3. The vulnerability causes a denial-of-service (DoS) condition due to resource exhaustion or system instability.
4. Alternatively, the vulnerability leads to information disclosure by exposing sensitive network data.
5. An attacker leverages the disclosed information to gain unauthorized access.
6. Further exploitation could enable arbitrary code execution, although this outcome is less likely given the nature of the vulnerability.

## Impact

Successful exploitation of CVE-2026-46099 could result in denial-of-service conditions, potentially disrupting network services. Information disclosure is another potential consequence, which could compromise sensitive network data. The number of potential victims is broad, as any system using the affected IPv6 functionalities is vulnerable until patched.

## Recommendation

*   Apply the security update released by Microsoft to patch CVE-2026-46099 immediately.
*   Monitor network traffic for suspicious IPv6 packets utilizing seg6 or rpl lwtunnels to identify potential exploitation attempts.
*   Enable network logging to capture relevant network events, which will aid in incident response and investigation.
