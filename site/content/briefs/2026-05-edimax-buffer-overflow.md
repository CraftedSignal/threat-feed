---
title: Edimax BR-6478AC Buffer Overflow Vulnerability (CVE-2026-9442)
slug: 2026-05-edimax-buffer-overflow
description: A buffer overflow vulnerability (CVE-2026-9442) exists in Edimax BR-6478AC version 1.23 in the formiNICSiteSurvey function of the /goform/formiNICSiteSurvey POST Request Handler, allowing a remote attacker to manipulate the selSSID argument to trigger a buffer overflow.
date: "2026-05-26T14:10:46Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - cve
  - buffer overflow
  - edimax
  - router
vendors:
  - Edimax
products:
  - BR-6478AC
  - BR-6478AC 1.23
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-9442
    cvss: 8.8
    epss: 0.00041
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9442
  - https://lavender-bicycle-a5a.notion.site/EDIMAX-BR6478ACV2-formiNICSiteSurvey-34b53a41781f8083b8dff46a2f02978f?source=copy_link
  - https://vuldb.com/submit/818451
  - https://vuldb.com/vuln/365423
  - https://vuldb.com/vuln/365423/cti
rules:
  - title: Detect CVE-2026-9442 Exploitation Attempt — Long selSSID Parameter
    description: Detects CVE-2026-9442 exploitation attempt — monitors web server logs for POST requests to /goform/formiNICSiteSurvey with an abnormally long selSSID parameter, indicating a potential buffer overflow exploit.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-9442 Exploitation Attempt — POST to formiNICSiteSurvey
    description: Detects CVE-2026-9442 exploitation attempt — monitors web server logs for POST requests to /goform/formiNICSiteSurvey which is the vulnerable endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A buffer overflow vulnerability, identified as CVE-2026-9442, affects Edimax BR-6478AC version 1.23. The vulnerability resides within the `formiNICSiteSurvey` function in the `/goform/formiNICSiteSurvey` component, specifically a POST Request Handler. By manipulating the `selSSID` argument, a remote attacker can trigger a buffer overflow. The exploit is publicly available, increasing the risk of exploitation. The vendor, Edimax, was notified about the vulnerability but did not respond. This poses a significant risk to users of the affected device, potentially leading to arbitrary code execution or denial of service.

## Attack Chain

1. The attacker identifies an Edimax BR-6478AC router running firmware version 1.23.
2. The attacker crafts a malicious HTTP POST request targeting the `/goform/formiNICSiteSurvey` endpoint.
3. The POST request includes the `selSSID` parameter with a value exceeding the expected buffer size.
4. The router's web server processes the POST request and passes the `selSSID` value to the `formiNICSiteSurvey` function.
5. Due to the insufficient buffer size and lack of input validation, the `selSSID` value overflows the buffer.
6. The buffer overflow overwrites adjacent memory regions, potentially including critical program data or execution pointers.
7. If the attacker carefully crafts the overflowed data, they can redirect execution to an attacker-controlled memory location.
8. The attacker gains the ability to execute arbitrary code on the router, potentially compromising the device and network.

## Impact

Successful exploitation of this vulnerability could allow an attacker to execute arbitrary code on the Edimax BR-6478AC router. This could lead to complete device compromise, allowing the attacker to modify router settings, intercept network traffic, or use the router as a pivot point for further attacks within the network. Given the public availability of the exploit, affected devices are at high risk of being targeted.

## Recommendation

*   Apply available patches from Edimax if they become available.
*   Monitor web server logs for suspicious POST requests to `/goform/formiNICSiteSurvey` with abnormally long `selSSID` values using the provided Sigma rule "Detect CVE-2026-9442 Exploitation Attempt — Long selSSID Parameter".
*   Implement rate limiting on POST requests to the `/goform/formiNICSiteSurvey` endpoint to mitigate potential denial-of-service attacks.
*   Consider disabling remote administration access to the router to reduce the attack surface.
*   Deploy the Sigma rule "Detect CVE-2026-9442 Exploitation Attempt — POST to formiNICSiteSurvey" to your SIEM to identify potential exploit attempts.
