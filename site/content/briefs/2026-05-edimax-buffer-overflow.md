---
title: Edimax EW-7438RPn Buffer Overflow Vulnerability (CVE-2026-9345)
slug: 2026-05-edimax-buffer-overflow
description: A remote buffer overflow vulnerability (CVE-2026-9345) exists in the formWizSurvey function of Edimax EW-7438RPn devices up to version 1.31, exploitable by manipulating the ssid/manualssid/ip/mask/gateway arguments, potentially leading to arbitrary code execution.
date: "2026-05-26T14:05:28Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - cve
  - buffer overflow
  - edimax
  - iot
  - remote code execution
vendors:
  - Edimax
products:
  - EW-7438RPn (<= 1.31)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-9345
    cvss: 8.8
    epss: 0.00043
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9345
  - https://github.com/wudipjq/my_vuln/blob/main/Edimax/vuln_3/3.md
  - https://vuldb.com/submit/811542
  - https://vuldb.com/submit/813886
  - https://vuldb.com/vuln/365308
  - https://vuldb.com/vuln/365308/cti
rules:
  - title: Detect CVE-2026-9345 Exploitation Attempt via Long Parameter Values
    description: Detects CVE-2026-9345 exploitation attempt — suspiciously long values in ssid, manualssid, ip, mask, or gateway parameters in requests to /goform/formWizSurvey, potentially indicating a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-9345 Exploitation Attempt via Shell Characters in Parameter Values
    description: Detects CVE-2026-9345 exploitation attempt — shell metacharacters in the ssid, manualssid, ip, mask, or gateway parameters when calling formWizSurvey, indicating command injection attempt.
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

A buffer overflow vulnerability, identified as CVE-2026-9345, affects Edimax EW-7438RPn devices running firmware version 1.31 and earlier. The vulnerability resides within the `formWizSurvey` function located in the `/goform/formWizSurvey` file of the `webs` component. Attackers can trigger the overflow by manipulating the `ssid`, `manualssid`, `ip`, `mask`, or `gateway` arguments. This vulnerability is remotely exploitable, allowing attackers to potentially execute arbitrary code on the affected device. Public exploits are available, increasing the risk of widespread exploitation. The vendor was notified but did not respond.

## Attack Chain

1.  Attacker identifies an Edimax EW-7438RPn device running a vulnerable firmware version (<= 1.31) accessible over the network.
2.  The attacker crafts a malicious HTTP request targeting the `/goform/formWizSurvey` endpoint.
3.  The request includes a payload designed to overflow the buffer in the `formWizSurvey` function. The `ssid`, `manualssid`, `ip`, `mask`, or `gateway` parameters are manipulated.
4.  The web server processes the request, and the `formWizSurvey` function attempts to handle the attacker-controlled input.
5.  Due to insufficient input validation, the buffer overflows, overwriting adjacent memory regions.
6.  The attacker leverages the overflow to inject malicious code into the device's memory.
7.  The injected code is executed, granting the attacker control over the device.
8.  The attacker can then use the compromised device to perform further malicious activities, such as joining a botnet, exfiltrating data, or pivoting to other devices on the network.

## Impact

Successful exploitation of CVE-2026-9345 allows attackers to gain complete control of the Edimax EW-7438RPn device. This can lead to a variety of negative consequences, including device hijacking, data theft, and the use of compromised devices in distributed denial-of-service (DDoS) attacks. Given the availability of public exploits, vulnerable devices are at high risk of compromise. The lack of vendor response exacerbates the problem, leaving users with no official patch or mitigation strategy.

## Recommendation

*   Deploy the Sigma rule "Detect CVE-2026-9345 Exploitation Attempt via Long Parameter Values" to identify requests with unusually long parameters to `/goform/formWizSurvey` in web server logs.
*   Deploy the Sigma rule "Detect CVE-2026-9345 Exploitation Attempt via Shell Characters in Parameter Values" to identify requests containing shell metacharacters within the `ssid`, `manualssid`, `ip`, `mask`, or `gateway` parameters.
*   Monitor network traffic for suspicious activity originating from Edimax EW-7438RPn devices, such as connections to known malicious IP addresses or unusual network protocols.
