---
title: Edimax BR-6478AC Stack-Based Buffer Overflow Vulnerability (CVE-2026-10125)
slug: 2026-05-edimax-buffer-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-10125) exists in the formPPPoESetup function of the /goform/formPPPoESetup file in Edimax BR-6478AC version 1.23, allowing a remote attacker to execute arbitrary code by manipulating the pppUserName argument in a POST request; a public exploit is available.
date: "2026-05-30T16:22:43Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - cve
  - CVE-2026-10125
  - buffer overflow
  - edimax
  - router
  - rce
vendors:
  - Edimax
products:
  - BR-6478AC 1.23
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-10125
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10125
  - https://lavender-bicycle-a5a.notion.site/EDIMAX-BR6478ACV2-formPPPoESetup-34b53a41781f80a1b029cb5ca5570afa?source=copy_link
  - https://vuldb.com/submit/818453
  - https://vuldb.com/vuln/367302
  - https://vuldb.com/vuln/367302/cti
rules:
  - title: Detect CVE-2026-10125 Exploitation Attempt via Long PPPoE Username
    description: Detects CVE-2026-10125 exploitation attempt via abnormally long pppUserName parameter in POST request to /goform/formPPPoESetup
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
  - title: Detect CVE-2026-10125 Exploitation Attempt via PPPoE Setup Endpoint Access
    description: Detects CVE-2026-10125 exploitation attempt by monitoring access to the /goform/formPPPoESetup endpoint using the POST method, which is unusual for normal operations.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
rules_count: 2
---

A stack-based buffer overflow vulnerability, CVE-2026-10125, has been identified in Edimax BR-6478AC version 1.23. The vulnerability lies within the `formPPPoESetup` function located in the `/goform/formPPPoESetup` file, a part of the POST Request Handler component. This flaw allows a remote attacker to execute arbitrary code by exploiting the `pppUserName` argument. The vulnerability is triggered via a specially crafted POST request. Given that a public exploit is available, this poses a significant risk to systems utilizing the affected Edimax router model, making them susceptible to remote code execution. Defenders should implement mitigations and detections to identify and prevent potential exploitation attempts.

## Attack Chain

1.  The attacker identifies an Edimax BR-6478AC 1.23 router exposed to the internet.
2.  The attacker crafts a malicious POST request targeting the `/goform/formPPPoESetup` endpoint.
3.  The POST request includes a `pppUserName` argument with a payload exceeding the buffer's capacity, triggering the stack-based buffer overflow.
4.  The overflow overwrites adjacent memory on the stack, including the return address.
5.  The overwritten return address points to attacker-controlled code or a ROP chain.
6.  The router processes the crafted POST request, executing the `formPPPoESetup` function.
7.  The function attempts to return, but instead jumps to the attacker-controlled address, leading to arbitrary code execution.
8.  The attacker gains control of the router and can perform actions such as modifying settings, eavesdropping on network traffic, or using the router as a botnet node.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to gain complete control over the Edimax BR-6478AC router. This can lead to a variety of malicious activities, including unauthorized network access, data theft, modification of router settings, and the use of the compromised device as part of a botnet. Given the availability of a public exploit, mass exploitation is possible, potentially impacting numerous home and small business networks.

## Recommendation

*   Deploy the Sigma rule `Detect CVE-2026-10125 Exploitation Attempt via Long PPPoE Username` to detect exploitation attempts in web server logs.
*   Inspect web server logs for POST requests to `/goform/formPPPoESetup` with abnormally long `pppUserName` values.
*   Monitor network traffic for suspicious activity originating from Edimax BR-6478AC devices.
