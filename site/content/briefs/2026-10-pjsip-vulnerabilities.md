---
title: Multiple Vulnerabilities in PJSIP
slug: 2026-10-pjsip-vulnerabilities
description: PJSIP contains multiple vulnerabilities, including heap buffer and integer overflows in SIP message processing, which can be exploited by an unauthenticated remote attacker to cause a denial-of-service condition or potentially execute arbitrary code.
date: "2026-10-15T16:23:03Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:octoprint:octoprint:*:*:*:*:*:*:*:*
  - cpe:2.3:a:librenms:librenms:*:*:*:*:*:*:*:*
vendors:
  - PJSIP
products:
  - PJSIP (< 2.14.1)
cves:
  - id: CVE-2024-51493
    cvss: 5.3
    epss: 0.00281
  - id: CVE-2024-51494
    cvss: 4.8
    epss: 0.00407
  - id: CVE-2024-51495
    cvss: 4.8
    epss: 0.00407
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3966
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-51493
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-51494
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-51495
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade PJSIP library to version 2.14.1 or later
      owner: IT Operations
      addresses: CVE-2024-51493, CVE-2024-51494, CVE-2024-51495
      evidence: Source advisory recommends version 2.14.1
---

PJSIP, a widely used open-source multimedia communication library, is vulnerable to multiple security flaws including heap buffer overflows and integer overflows (CVE-2024-51493, CVE-2024-51494, and CVE-2024-51495). These vulnerabilities stem from improper processing of incoming SIP messages. An unauthenticated remote attacker can exploit these flaws by sending specially crafted SIP packets to an application utilizing the affected PJSIP versions. Successful exploitation may result in unauthorized data manipulation, information disclosure, or a denial-of-service (DoS) state, where the affected service crashes or becomes unresponsive. Versions prior to 2.14.1 are confirmed to be vulnerable. Defenders should prioritize updating instances of PJSIP to version 2.14.1 or later to mitigate these risks.

## Impact

Successful exploitation of these vulnerabilities allows an unauthenticated remote attacker to disrupt communication services via a denial-of-service, or potentially gain control over the affected application through memory corruption. PJSIP is integrated into numerous VoIP, unified communications, and softphone products, making this impact widespread across organizations relying on real-time communication infrastructure.

## Recommendation

* Patch all instances of PJSIP by upgrading to version 2.14.1 or later to address CVE-2024-51493, CVE-2024-51494, and CVE-2024-51495.
* Audit network logs for anomalous SIP traffic or malformed packets directed toward VoIP infrastructure and softphone services.
* Review vendor-specific advisories for any proprietary products that bundle PJSIP, as they may require product-specific patches beyond the library update.
