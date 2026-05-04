---
title: Totolink N300RH Buffer Overflow Vulnerability in setWanConfig
slug: 2026-05-totolink-n300rh-buffer-overflow
description: A buffer overflow vulnerability exists in Totolink N300RH version 3.2.4-B20220812, specifically affecting the setWanConfig function within the /cgi-bin/cstecgi.cgi file, allowing a remote attacker to exploit it by manipulating the priDns argument in a POST request.
date: "2026-05-04T10:16:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - buffer-overflow
  - router
  - cve-2026-7749
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
  - id: CVE-2026-7749
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7749
  - https://lavender-bicycle-a5a.notion.site/TOTOLINK-N300RH-setWanConfig-34553a41781f80ed8500d9b8d54074f2
  - https://vuldb.com/vuln/360924
rules:
  - title: Detect Suspiciously Long priDns Values in POST Requests to cstecgi.cgi
    description: Detects potential buffer overflow attempts in Totolink N300RH by monitoring the length of the priDns parameter in POST requests to the cstecgi.cgi endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect POST Requests to cstecgi.cgi with Common Exploit Payloads
    description: Detects potential command injection attempts in Totolink N300RH by monitoring POST requests to the cstecgi.cgi endpoint containing shell metacharacters and commands.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A buffer overflow vulnerability has been identified in Totolink N300RH router version 3.2.4-B20220812. The vulnerability resides in the `setWanConfig` function within the `/cgi-bin/cstecgi.cgi` file, which handles POST requests. An attacker can exploit this vulnerability by manipulating the `priDns` argument in a crafted POST request. The vulnerability allows for remote exploitation, meaning an attacker does not need local access to the device. Public exploits for this vulnerability are already available, increasing the risk of exploitation. This vulnerability was published on 2026-05-04.

## Attack Chain

1.  The attacker identifies a vulnerable Totolink N300RH router running firmware version 3.2.4-B20220812.
2.  The attacker crafts a malicious POST request targeting the `/cgi-bin/cstecgi.cgi` endpoint.
3.  Within the POST request, the attacker includes the `priDns` argument with a value exceeding the buffer size.
4.  The `setWanConfig` function processes the `priDns` argument without proper bounds checking.
5.  The oversized `priDns` value overwrites adjacent memory on the stack, potentially including control flow data.
6.  The attacker gains control of the program execution flow by overwriting the return address.
7.  The attacker executes arbitrary code on the router, potentially gaining a shell.
8.  The attacker could then use the compromised router to perform lateral movement, exfiltrate data, or establish a persistent backdoor.

## Impact

Successful exploitation of this buffer overflow vulnerability can lead to complete compromise of the Totolink N300RH router. An attacker could gain unauthorized access to the device's configuration, intercept network traffic, or use the router as a pivot point to attack other devices on the network. Given that public exploits are available, a wide range of attackers could potentially exploit this vulnerability. The CVSS v3.1 base score is 8.8 (HIGH).

## Recommendation

*   Monitor web server logs for POST requests to `/cgi-bin/cstecgi.cgi` with abnormally long `priDns` values to detect potential exploitation attempts using the provided Sigma rule.
*   Implement network intrusion detection system (NIDS) rules to detect and block malicious POST requests targeting `/cgi-bin/cstecgi.cgi`.
*   Contact Totolink for a security patch or firmware update to address CVE-2026-7749.
