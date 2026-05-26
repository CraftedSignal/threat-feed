---
title: Edimax BR-6428NS Buffer Overflow Vulnerability (CVE-2026-9295)
slug: 2026-05-edimax-buffer-overflow
description: A buffer overflow vulnerability (CVE-2026-9295) exists in the formWirelessTbl function of the /goform/formWirelessTbl file in Edimax BR-6428NS 1.10, caused by manipulating the vapurl argument via a POST request, allowing remote attackers to execute arbitrary code.
date: "2026-05-26T14:05:11Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - buffer-overflow
  - router
  - web-application
vendors:
  - Edimax
products:
  - BR-6428NS 1.10
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-9295
    cvss: 8.8
    epss: 0.00015
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9295
  - https://lavender-bicycle-a5a.notion.site/EDIMAX-BR-6428NS-formWirelessTbl-34b53a41781f80a89cadcc9b5293086e?source=copy_link
  - https://vuldb.com/submit/811534
  - https://vuldb.com/vuln/365242
  - https://vuldb.com/vuln/365242/cti
rules:
  - title: Detects CVE-2026-9295 Exploitation Attempt — Edimax BR-6428NS Buffer Overflow
    description: Detects CVE-2026-9295 exploitation attempt — HTTP POST request to /goform/formWirelessTbl with an overly long vapurl parameter, indicating a potential buffer overflow attempt
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

A buffer overflow vulnerability has been identified in Edimax BR-6428NS version 1.10. The vulnerability resides within the `formWirelessTbl` function of the `/goform/formWirelessTbl` file, specifically in the POST Request Handler component. Successful exploitation of this vulnerability, designated as CVE-2026-9295, allows remote attackers to execute arbitrary code due to insufficient bounds checking when handling the `vapurl` argument. A publicly available exploit exists, increasing the risk of active exploitation. The vendor was notified but did not respond.

## Attack Chain

1.  Attacker identifies an Edimax BR-6428NS router running firmware version 1.10.
2.  Attacker crafts a malicious POST request targeting the `/goform/formWirelessTbl` endpoint.
3.  The POST request includes the `vapurl` argument with a value exceeding the expected buffer size.
4.  The `formWirelessTbl` function processes the crafted POST request without proper bounds checking.
5.  The oversized `vapurl` value overflows the buffer, overwriting adjacent memory regions.
6.  The attacker carefully crafts the overflow to overwrite the return address on the stack.
7.  Upon returning from the `formWirelessTbl` function, execution is redirected to the attacker-controlled address.
8.  The attacker gains arbitrary code execution on the router, potentially leading to full system compromise.

## Impact

Successful exploitation of CVE-2026-9295 can lead to complete compromise of the Edimax BR-6428NS router. Attackers can leverage this vulnerability to execute arbitrary code, potentially installing malware, creating backdoors, or using the compromised router as part of a botnet. Given the widespread use of such routers in home and small business networks, this vulnerability poses a significant risk to network security and data confidentiality.

## Recommendation

*   Apply a network-level block to prevent access to the /goform/formWirelessTbl endpoint from untrusted sources (firewall).
*   Monitor web server logs for POST requests to `/goform/formWirelessTbl` containing abnormally long `vapurl` parameters (webserver rule).
*   Deploy the provided Sigma rule to detect potential exploitation attempts targeting the vulnerable endpoint.
*   Consider replacing the Edimax BR-6428NS 1.10 router with a more secure alternative from a vendor that provides timely security updates if a patch is unavailable.
