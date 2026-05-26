---
title: Edimax EW-7438RPn Buffer Overflow Vulnerability (CVE-2026-9360)
slug: 2026-05-edimax-buffer-overflow
description: A buffer overflow vulnerability (CVE-2026-9360) exists in the Edimax EW-7438RPn version 1.28a within the function formwlencrypt24g of the /goform/formwlencrypt24g component's POST Request Handler, where manipulation of the key1 argument can lead to a remote attack.
date: "2026-05-26T13:45:45Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - cve
  - buffer overflow
  - web application
vendors:
  - Edimax
products:
  - EW-7438RPn
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-9360
    cvss: 8.8
    epss: 0.00041
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9360
  - https://lavender-bicycle-a5a.notion.site/EDIMAX-EW-7438RPn-Mini-formwlencrypt24g-34b53a41781f808c99bcd687b351750b?source=copy_link
  - https://vuldb.com/submit/811544
  - https://vuldb.com/vuln/365323
  - https://vuldb.com/vuln/365323/cti
rules:
  - title: Detect CVE-2026-9360 Exploitation Attempt
    description: Detects CVE-2026-9360 exploitation attempt — POST request to /goform/formwlencrypt24g with an overly long key1 parameter, indicating a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A buffer overflow vulnerability, identified as CVE-2026-9360, affects the Edimax EW-7438RPn Wi-Fi extender, specifically version 1.28a. The vulnerability resides in the `formwlencrypt24g` function within the `/goform/formwlencrypt24g` component, which handles POST requests. Successful exploitation of this flaw allows remote attackers to execute arbitrary code due to insufficient bounds checking when handling the `key1` argument. Publicly available exploits exist, increasing the risk of widespread exploitation. The vendor was contacted regarding this vulnerability but has not responded.

## Attack Chain

1.  Attacker identifies an Edimax EW-7438RPn device running firmware version 1.28a.
2.  Attacker crafts a malicious POST request targeting the `/goform/formwlencrypt24g` endpoint.
3.  The POST request includes the `key1` argument with a value exceeding the buffer's allocated size.
4.  The `formwlencrypt24g` function processes the POST request without proper bounds checking on the `key1` argument.
5.  The excessive size of the `key1` value triggers a buffer overflow.
6.  The buffer overflow overwrites adjacent memory regions, potentially including critical program data or execution pointers.
7.  The attacker gains the ability to execute arbitrary code on the device.
8.  The attacker can then use this access to pivot into the network, reconfigure the device, or cause a denial of service.

## Impact

Successful exploitation of CVE-2026-9360 allows a remote attacker to execute arbitrary code on the vulnerable Edimax EW-7438RPn device. This can lead to complete compromise of the device, enabling the attacker to perform actions such as eavesdropping on network traffic, modifying device settings, or using the device as a launchpad for further attacks within the network. Given the nature of Wi-Fi extenders, a successful attack can compromise the security of the entire network it serves.

## Recommendation

*   Implement the provided Sigma rule `Detect CVE-2026-9360 Exploitation Attempt` to identify malicious POST requests targeting the vulnerable endpoint `/goform/formwlencrypt24g`.
*   Closely monitor network traffic for suspicious POST requests with abnormally large `key1` parameter values.
*   Consider deploying a web application firewall (WAF) rule to filter out requests that exploit this vulnerability.
*   Since the vendor is unresponsive, end-of-life the Edimax EW-7438RPn 1.28a devices and replace them with more secure alternatives.
