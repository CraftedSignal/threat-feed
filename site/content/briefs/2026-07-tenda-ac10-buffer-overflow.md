---
title: Tenda AC10 Buffer Overflow Vulnerability (CVE-2026-16248)
slug: 2026-07-tenda-ac10-buffer-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-16248) has been identified in Tenda AC10 firmware version 16.03.10.09_multi_TDE01, residing in the fromAdvSetLanip function of the /goform/AdvSetLanip file within the httpd/netctrl component, which can be remotely exploited by manipulating the GetValue/SetValue argument, with a public exploit now available.
date: "2026-07-20T13:29:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - buffer-overflow
  - rce
  - firmware
  - router
  - web-vulnerability
  - cve
vendors:
  - Tenda
products:
  - AC10 16.03.10.09_multi_TDE01
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be performed from remote. The exploit has been made public and could be used.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: The manipulation of the argument GetValue/SetValue results in stack-based buffer overflow.
    confidence_band: high
cves:
  - id: CVE-2026-16248
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16248
  - https://github.com/teiwiet/tenda-ac10-vulnerabilities/blob/main/advisory-fromAdvSetLanip.md
  - https://vuldb.com/cve/CVE-2026-16248
  - https://vuldb.com/submit/858411
  - https://vuldb.com/vuln/380539
  - https://vuldb.com/vuln/380539/cti
  - https://www.tenda.com.cn/
iocs:
  - type: url
    value: https://github.com/teiwiet/tenda-ac10-vulnerabilities/blob/main/advisory-fromAdvSetLanip.md
  - type: url
    value: https://vuldb.com/cve/CVE-2026-16248
  - type: url
    value: https://vuldb.com/submit/858411
  - type: url
    value: https://vuldb.com/vuln/380539
  - type: url
    value: https://vuldb.com/vuln/380539/cti
  - type: url
    value: https://www.tenda.com.cn/
ioc_counts:
  url: 6
---

A critical stack-based buffer overflow vulnerability, identified as CVE-2026-16248, affects the Tenda AC10 router firmware version 16.03.10.09_multi_TDE01. This flaw is located within the `fromAdvSetLanip` function of the `/goform/AdvSetLanip` file, part of the `httpd/netctrl` component. Attackers can remotely exploit this vulnerability by manipulating the `GetValue/SetValue` arguments, which can lead to arbitrary code execution and full control over the device. The exploit code for this vulnerability has been publicly released, increasing the risk of widespread exploitation. This poses a significant threat to organizations and individuals using the affected Tenda AC10 routers, as compromised devices can be used for unauthorized network access, data exfiltration, or further attacks on internal systems.

## Attack Chain

1. An attacker identifies a vulnerable Tenda AC10 router exposed to the internet.
2. The attacker crafts a specially designed HTTP request targeting the `/goform/AdvSetLanip` endpoint on the router's web interface.
3. The malicious HTTP request includes crafted `GetValue` or `SetValue` arguments designed to exceed the buffer limits.
4. The `fromAdvSetLanip` function processes the malformed arguments, leading to a stack-based buffer overflow.
5. The buffer overflow overwrites critical memory regions, allowing the attacker to inject and execute arbitrary code on the router.
6. Upon successful code execution, the attacker gains full control over the Tenda AC10 router.
7. The compromised router can then be used as a pivot point for further attacks on the internal network, to monitor or intercept traffic, or to alter device configurations.

## Impact

Successful exploitation of CVE-2026-16248 grants attackers complete control over the affected Tenda AC10 router. This can lead to severe consequences including, but not limited to, unauthorized access to the network connected to the router, interception or manipulation of network traffic, and potential for data exfiltration. Attackers could also reconfigure the router to redirect users to malicious websites, launch denial-of-service attacks, or establish persistent backdoors. The public availability of exploit code significantly increases the likelihood of widespread attacks against unpatched devices, posing a critical risk to any organizations or home users utilizing this specific router model.

## Recommendation

* Immediately update Tenda AC10 router firmware to the latest secure version once released by the vendor to patch CVE-2026-16248.
* Monitor webserver logs for the `/goform/AdvSetLanip` endpoint for unusually long or malformed `GetValue` or `SetValue` parameters as described in the `Overview` section.
* Review network firewall rules to restrict access to router administration interfaces from untrusted external networks.
