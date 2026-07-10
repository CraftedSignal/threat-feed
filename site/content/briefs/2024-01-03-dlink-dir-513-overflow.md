---
title: D-Link DIR-513 v1.10 Remote Buffer Overflow Vulnerability (CVE-2026-6013)
slug: 2024-01-03-dlink-dir-513-overflow
description: A remote buffer overflow vulnerability exists in the formSetRoute function of the D-Link DIR-513 v1.10 router's web interface, triggered by manipulating the 'curTime' argument in a POST request, potentially allowing unauthenticated attackers to execute arbitrary code; this vulnerability affects an end-of-life product with a public exploit.
date: "2024-01-03T18:45:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - CVE-2026-6013
  - buffer-overflow
  - dlink
  - router
vendors:
  - D-Link
products:
  - DIR-513
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-6013
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6013
  - https://lavender-bicycle-a5a.notion.site/D-Link-DIR-513-formSetRoute-33153a41781f80f7aed1d3614c199d85?source=copy_link
  - https://vuldb.com/vuln/356569
rules:
  - title: Detect Suspicious Long curTime Parameter
    description: Detects unusually long 'curTime' parameters in POST requests to '/goform/formSetRoute', indicative of a potential buffer overflow attempt (CVE-2026-6013).
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Access to D-Link DIR-513 formSetRoute
    description: Detects POST requests to the /goform/formSetRoute endpoint on D-Link DIR-513 routers, which may indicate attempts to exploit CVE-2026-6013.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-6013 describes a critical buffer overflow vulnerability in the D-Link DIR-513 router, specifically version 1.10. The vulnerability lies within the `formSetRoute` function of the `/goform/formSetRoute` file, which handles POST requests. An attacker can exploit this flaw by manipulating the `curTime` argument in a crafted POST request, leading to a buffer overflow. Successful exploitation could allow a remote attacker to execute arbitrary code on the device. Public exploits are reportedly available, increasing the risk of exploitation. However, D-Link has reached end-of-life for the DIR-513 product line, meaning no patch will be released, so any vulnerable device needs to be taken offline.

## Attack Chain

1.  The attacker identifies a vulnerable D-Link DIR-513 router (v1.10) accessible over the network.
2.  The attacker crafts a malicious HTTP POST request targeting the `/goform/formSetRoute` endpoint.
3.  Within the POST request, the attacker includes the `curTime` argument with a value exceeding the expected buffer size.
4.  The web server on the D-Link DIR-513 receives the malicious POST request.
5.  The `formSetRoute` function processes the request and attempts to copy the overly long `curTime` value into a fixed-size buffer without proper bounds checking.
6.  The buffer overflow occurs, overwriting adjacent memory regions.
7.  By carefully crafting the overflowing data, the attacker can overwrite critical data such as return addresses.
8.  When the `formSetRoute` function returns, it jumps to the attacker-controlled address, leading to arbitrary code execution on the router, achieving full system compromise.

## Impact

Successful exploitation of CVE-2026-6013 can lead to arbitrary code execution on the vulnerable D-Link DIR-513 router. This could allow an attacker to gain complete control of the device, potentially enabling them to eavesdrop on network traffic, modify router settings, or use the compromised device as a bot in a larger botnet. The vulnerability affects all D-Link DIR-513 v1.10 devices still in operation, although the exact number of vulnerable devices is unknown due to the product's end-of-life status.

## Recommendation

*   Identify and immediately decommission any D-Link DIR-513 v1.10 routers on your network to eliminate the risk of exploitation of CVE-2026-6013.
*   Deploy the provided Sigma rule to detect suspicious POST requests to `/goform/formSetRoute` with abnormally long `curTime` parameters (see Sigma rule: "Detect Suspicious Long curTime Parameter").
*   Monitor web server logs for unusual activity related to the `/goform/formSetRoute` endpoint, as this is the primary attack vector (see logsource: category: webserver).
