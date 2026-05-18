---
title: Edimax BR-6428NS Buffer Overflow Vulnerability (CVE-2026-8775)
slug: 2026-05-edimax-buffer-overflow
description: A buffer overflow vulnerability (CVE-2026-8775) exists in the formL2TPSetup function of the /goform/formL2TPSetup component in Edimax BR-6428NS version 1.10, triggered by manipulating the L2TPUserName argument in a POST request, enabling remote exploitation.
date: "2026-05-18T02:18:54Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - buffer-overflow
  - router
  - CVE-2026-8775
vendors:
  - Edimax
products:
  - BR-6428NS 1.10
cves:
  - id: CVE-2026-8775
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8775
rules:
  - title: Detect CVE-2026-8775 Exploitation Attempt
    description: Detects CVE-2026-8775 exploitation attempt — Monitors web server logs for POST requests to the /goform/formL2TPSetup endpoint with an overly long L2TPUserName parameter, indicating a buffer overflow attempt.
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

A buffer overflow vulnerability, identified as CVE-2026-8775, has been discovered in Edimax BR-6428NS router firmware version 1.10. The vulnerability is located within the `formL2TPSetup` function of the `/goform/formL2TPSetup` component, specifically the POST Request Handler. By manipulating the `L2TPUserName` argument in a POST request, a remote attacker can trigger a buffer overflow. Publicly available exploit code exists, increasing the risk of exploitation. The vendor was notified about this vulnerability but has not responded, raising concerns about potential patching and future security support for this device.

## Attack Chain

1.  The attacker identifies an Edimax BR-6428NS router running firmware version 1.10.
2.  The attacker crafts a malicious HTTP POST request targeting the `/goform/formL2TPSetup` endpoint.
3.  Within the POST request, the attacker includes the `L2TPUserName` parameter with a value exceeding the buffer's expected size.
4.  The web server processes the POST request and calls the `formL2TPSetup` function.
5.  The `formL2TPSetup` function copies the overly long `L2TPUserName` value into a fixed-size buffer without proper bounds checking.
6.  The buffer overflow corrupts adjacent memory regions, potentially overwriting critical data or control flow pointers.
7.  The attacker achieves arbitrary code execution on the router.
8.  The attacker can then leverage the compromised device for malicious purposes, such as network pivoting, data exfiltration, or denial-of-service attacks.

## Impact

Successful exploitation of CVE-2026-8775 can lead to complete compromise of the Edimax BR-6428NS router. This allows attackers to gain control of the device, potentially enabling them to monitor network traffic, intercept sensitive data, or use the router as a launchpad for further attacks within the network. Given the availability of public exploits, organizations and individuals using this router model are at significant risk.

## Recommendation

*   Apply firmware updates from Edimax if they become available to patch CVE-2026-8775.
*   Deploy the Sigma rule `Detect CVE-2026-8775 Exploitation Attempt` to identify malicious POST requests targeting the vulnerable endpoint and parameter.
*   Implement network segmentation to limit the impact of a compromised router.
