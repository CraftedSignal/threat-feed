---
title: TRENDnet TEW-432BRP Stack-Based Buffer Overflow Vulnerability (CVE-2026-10120)
slug: 2026-05-trendnet-buffer-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-10120) exists in TRENDnet TEW-432BRP version 3.10B20, allowing a remote attacker to execute arbitrary code by manipulating the firewall_name argument in the formSetFirewallRule function; the vendor has declared the product EOL and will not issue a patch.
date: "2026-05-30T15:17:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - buffer overflow
  - router
  - cve
vendors:
  - TRENDnet
products:
  - TEW-432BRP 3.10B20
cves:
  - id: CVE-2026-10120
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10120
  - CVE-2026-10120
rules:
  - title: Detect CVE-2026-10120 Exploitation Attempt — Long Firewall Name
    description: Detects CVE-2026-10120 exploitation attempt — Suspiciously long firewall_name parameter in a POST request to /goform/formSetFirewallRule.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-10120 Exploitation Attempt — Stack Overflow Header
    description: Detects CVE-2026-10120 exploitation attempt — Suspicious header in a POST request to /goform/formSetFirewallRule that could be used to trigger the overflow.
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

CVE-2026-10120 is a stack-based buffer overflow vulnerability affecting TRENDnet TEW-432BRP router version 3.10B20. The vulnerability resides in the `formSetFirewallRule` function within the `/goform/formSetFirewallRule` file. A remote attacker can exploit this by sending a specially crafted request to the router's web interface, specifically manipulating the `firewall_name` argument. This overflow could allow an attacker to execute arbitrary code on the device. TRENDnet has stated that the TEW-432BRP has been end-of-life (EOL) since 2009 and they will not be providing a patch for this vulnerability. This poses a risk to users who are still operating this outdated device on their networks.

## Attack Chain

1.  Attacker identifies a vulnerable TRENDnet TEW-432BRP router running firmware version 3.10B20.
2.  Attacker sends an HTTP POST request to `/goform/formSetFirewallRule`.
3.  The POST request includes the `firewall_name` parameter.
4.  The attacker crafts the `firewall_name` parameter with a string longer than the expected buffer size.
5.  The `formSetFirewallRule` function processes the `firewall_name` argument without proper bounds checking.
6.  The excessive length of the `firewall_name` string causes a stack-based buffer overflow, overwriting adjacent memory on the stack.
7.  The attacker overwrites the return address on the stack with an address pointing to malicious code injected elsewhere in the request or pre-existing on the device.
8.  When the `formSetFirewallRule` function returns, execution jumps to the attacker-controlled address, allowing the attacker to execute arbitrary code on the router.

## Impact

Successful exploitation of CVE-2026-10120 allows a remote attacker to execute arbitrary code on the vulnerable TRENDnet TEW-432BRP router. This could lead to complete compromise of the device, allowing the attacker to control network traffic, intercept sensitive information, or use the router as a pivot point for further attacks within the network. As the device is EOL, users are unlikely to receive security updates and will remain vulnerable unless they replace the device.

## Recommendation

*   Identify and replace any TRENDnet TEW-432BRP devices version 3.10B20 on your network due to the lack of vendor support and available patches for CVE-2026-10120.
*   Monitor network traffic for suspicious POST requests to `/goform/formSetFirewallRule` with unusually long `firewall_name` parameters using the provided Sigma rule.
*   Implement network segmentation to limit the potential impact of a compromised device.
