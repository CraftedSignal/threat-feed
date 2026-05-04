---
title: Totolink N300RH Buffer Overflow Vulnerability (CVE-2026-7750)
slug: 2026-05-totolink-buffer-overflow
description: A buffer overflow vulnerability exists in Totolink N300RH 3.2.4-B20220812 allowing remote attackers to execute arbitrary code by manipulating the mac_address argument in the setMacFilterRules function of the /cgi-bin/cstecgi.cgi POST request handler.
date: "2026-05-04T10:16:01Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - buffer-overflow
  - router
  - cve
  - webserver
vendors:
  - Totolink
products:
  - N300RH 3.2.4-B20220812
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7750
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7750
  - https://lavender-bicycle-a5a.notion.site/TOTOLINK-N300RH-setMacFilterRules-34553a41781f809cb952cdcb71ce90d8
  - https://vuldb.com/submit/807204
  - https://vuldb.com/vuln/360925
  - https://vuldb.com/vuln/360925/cti
  - https://www.totolink.net/
rules:
  - title: Detect Suspiciously Long MAC Address in POST Request to Totolink CGI
    description: Detects abnormally long mac_address parameters in POST requests to cstecgi.cgi, indicative of a buffer overflow attempt in Totolink devices.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Access to Totolink cstecgi.cgi Endpoint
    description: Detects access to the cstecgi.cgi endpoint, which is known to be vulnerable on Totolink devices.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A buffer overflow vulnerability, identified as CVE-2026-7750, affects Totolink N300RH router version 3.2.4-B20220812. The vulnerability resides in the `setMacFilterRules` function within the `/cgi-bin/cstecgi.cgi` file, which handles POST requests. Attackers can exploit this flaw by sending a specially crafted POST request with an overly long `mac_address` parameter, triggering a buffer overflow. Successful exploitation allows for arbitrary code execution on the device. The vulnerability is remotely exploitable, and a public exploit is available, increasing the risk of widespread attacks. Defenders should prioritize patching or mitigating this vulnerability to prevent potential compromise of affected devices.

## Attack Chain

1. The attacker identifies a vulnerable Totolink N300RH router running firmware version 3.2.4-B20220812.
2. The attacker crafts a malicious POST request targeting the `/cgi-bin/cstecgi.cgi` endpoint.
3. Within the POST request, the attacker includes the `mac_address` parameter, injecting a string longer than the buffer allocated for it.
4. The `setMacFilterRules` function processes the POST request without proper bounds checking on the `mac_address` argument.
5. The overly long `mac_address` value overflows the buffer, overwriting adjacent memory regions.
6. The attacker carefully crafts the overflow to overwrite the return address, redirecting execution flow to attacker-controlled code.
7. The injected code executes with the privileges of the web server, allowing the attacker to execute arbitrary commands.
8. The attacker gains complete control over the router, potentially using it for further malicious activities such as network pivoting, data exfiltration, or denial-of-service attacks.

## Impact

Successful exploitation of CVE-2026-7750 allows a remote attacker to execute arbitrary code on the vulnerable Totolink N300RH device. This could lead to a complete compromise of the router, allowing the attacker to control network traffic, steal sensitive information, or use the router as a bot in a larger attack. Given the public availability of the exploit, a large number of unpatched devices could be vulnerable to automated attacks, potentially impacting thousands of users.

## Recommendation

*   Apply available patches or firmware updates provided by Totolink to address CVE-2026-7750.
*   Implement network intrusion detection system (IDS) rules to detect and block suspicious POST requests targeting the `/cgi-bin/cstecgi.cgi` endpoint with excessively long `mac_address` parameters.
*   Deploy the Sigma rules in this brief to your SIEM to detect exploitation attempts.
*   Monitor web server logs for unusual POST requests to `/cgi-bin/cstecgi.cgi`, focusing on requests with large `mac_address` values.
