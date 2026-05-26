---
title: Edimax BR-6478AC Buffer Overflow Vulnerability (CVE-2026-9443)
slug: 2026-05-edimax-buffer-overflow
description: A buffer overflow vulnerability (CVE-2026-9443) exists in Edimax BR-6478AC version 1.23 in the formL2TPSetup function within the /goform/formL2TPSetup file, allowing a remote attacker to trigger a buffer overflow by manipulating the L2TPUserName argument, with public exploits available.
date: "2026-05-26T14:11:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - buffer overflow
  - edimax
  - network device
vendors:
  - Edimax
products:
  - BR-6478AC
  - BR-6478AC 1.23
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-9443
    cvss: 8.8
    epss: 0.00041
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9443
  - https://lavender-bicycle-a5a.notion.site/EDIMAX-BR6478ACV2-formL2TPSetup-34b53a41781f809e9c30c1260cc5d92e?source=copy_link
  - https://vuldb.com/submit/818452
  - https://vuldb.com/vuln/365424
  - https://vuldb.com/vuln/365424/cti
rules:
  - title: Detect CVE-2026-9443 Exploitation Attempt — Malicious L2TPUserName Parameter
    description: Detects CVE-2026-9443 exploitation attempt —  identifies HTTP POST requests to /goform/formL2TPSetup with an unusually long L2TPUserName parameter, suggesting a buffer overflow attack
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-9443 Exploitation Attempt — Suspicious POST Request to formL2TPSetup
    description: Detects CVE-2026-9443 exploitation attempt — identifies HTTP POST requests to /goform/formL2TPSetup with L2TPUserName exceeding normal bounds.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A buffer overflow vulnerability, identified as CVE-2026-9443, has been discovered in the Edimax BR-6478AC router, specifically version 1.23. This vulnerability resides within the `formL2TPSetup` function of the `/goform/formL2TPSetup` file, which is part of the POST Request Handler component. Successful exploitation allows a remote attacker to execute arbitrary code on the affected device by overflowing a buffer. The vulnerability is triggered by manipulating the `L2TPUserName` argument in a crafted POST request. A public exploit for this vulnerability is available, increasing the risk of exploitation. The vendor was notified but did not respond.

## Attack Chain

1. The attacker identifies an Edimax BR-6478AC router version 1.23 exposed to the internet.
2. The attacker crafts a malicious HTTP POST request targeting the `/goform/formL2TPSetup` endpoint.
3. The POST request includes the `L2TPUserName` argument with a string exceeding the buffer's allocated size.
4. The `formL2TPSetup` function processes the request without proper bounds checking.
5. The excessive data written to the `L2TPUserName` buffer overflows into adjacent memory regions, potentially overwriting critical data or code.
6. The overwritten memory may include function return addresses or other control data.
7. When the `formL2TPSetup` function returns, the overwritten return address redirects execution to attacker-controlled code.
8. The attacker gains arbitrary code execution on the router, potentially allowing for device takeover or denial of service.

## Impact

Successful exploitation of this buffer overflow vulnerability (CVE-2026-9443) in Edimax BR-6478AC 1.23 routers can lead to complete compromise of the device. This could allow attackers to perform a variety of malicious actions, including eavesdropping on network traffic, modifying router configurations, using the router as part of a botnet, or causing a denial-of-service condition. Given the availability of public exploits, unpatched routers are at high risk. The number of potentially affected devices is unknown but could be significant given the popularity of Edimax routers.

## Recommendation

*   Deploy the Sigma rule `Detect CVE-2026-9443 Exploitation Attempt — Malicious L2TPUserName Parameter` to your SIEM to identify potential exploitation attempts based on the length of the L2TPUserName parameter.
*   Deploy the Sigma rule `Detect CVE-2026-9443 Exploitation Attempt — Suspicious POST Request to formL2TPSetup` to detect POST requests with overly long L2TPUserName values sent to the vulnerable endpoint.
*   Monitor web server logs for HTTP POST requests to `/goform/formL2TPSetup` with unusually long `L2TPUserName` parameters, as this is indicative of a potential buffer overflow attempt.
