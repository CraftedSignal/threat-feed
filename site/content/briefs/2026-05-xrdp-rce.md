---
title: 'CVE-2025-68670: xrdp Pre-Authentication Remote Code Execution'
slug: 2026-05-xrdp-rce
description: A pre-authentication remote code execution vulnerability exists in xrdp versions prior to 0.10.5, triggered by a buffer overflow in the xrdp_wm_parse_domain_information function when parsing a specially crafted domain name, allowing attackers to overwrite the return address and execute arbitrary code.
date: "2026-05-08T08:00:54Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:neutrinolabs:xrdp:*:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*
tags:
  - rce
  - xrdp
  - cve-2025-68670
  - remote-desktop
  - linux
vendors:
  - Kaspersky
  - neutrinolabs
products:
  - Kaspersky USB Redirector
  - Kaspersky Thin Client
  - xrdp
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1213
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2025-68670
    cvss: 9.1
    epss: 0.00123
references:
  - https://securelist.com/cve-2025-68670/119742/
  - https://www.cve.org/CVERecord?id=CVE-2025-68670
  - https://github.com/neutrinolabs/xrdp/security/advisories/GHSA-rwvg-gp87-gh6f
rules:
  - title: Detect CVE-2025-68670 Exploitation Attempt via Long Domain
    description: Detects CVE-2025-68670 exploitation attempt — Detects RDP connections with domain names starting with an underscore and exceeding a length of 255 characters, indicative of a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1213
    data_sources:
      - network_connection
      - windows
  - title: Detect CVE-2025-68670 Exploitation Attempt via process creation
    description: Detects CVE-2025-68670 exploitation attempt — Detects process creations originating from xrdp processes, which may indicate code execution following a successful buffer overflow.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2025-68670 is a critical remote code execution vulnerability discovered in the xrdp server, affecting versions prior to 0.10.5. The vulnerability resides within the `xrdp_wm_parse_domain_information` function, which processes the domain name provided by the client during the Secure Settings Exchange of the RDP connection establishment. An attacker can exploit this vulnerability by sending a crafted domain name that starts with an underscore, causing a buffer overflow in the `resultIP` buffer. This overflow allows the attacker to overwrite the return address on the stack, enabling arbitrary code execution within the context of the compromised process. The vulnerability was identified during a security assessment of Kaspersky USB Redirector. The maintainers of xrdp patched the vulnerability in version 0.10.5 and backported the fix to versions 0.9.27 and 0.10.4.1. Exploitation does not require authentication, making it a highly critical vulnerability.

## Attack Chain

1.  Attacker initiates an RDP connection to the target xrdp server.
2.  The client and server begin the Secure Settings Exchange.
3.  The client sends a Client Info PDU containing a crafted domain name within the TS_INFO_PACKET structure. The malicious domain name starts with an underscore and is longer than 255 characters.
4.  The server receives the domain name and passes it to the `xrdp_wm_parse_domain_information` function.
5.  The `xrdp_wm_parse_domain_information` function checks if the domain name starts with an underscore.
6.  Because the domain name begins with an underscore, the function attempts to copy a portion of the domain name into the `resultIP` buffer using `g_strncpy`.
7.  Due to the crafted domain name's length (longer than 255 bytes), `g_strncpy` overflows the `resultIP` buffer, overwriting the return address on the stack.
8.  The `xrdp_wm_parse_domain_information` function returns, and the overwritten return address is used, redirecting execution to the attacker's injected code, achieving arbitrary code execution.

## Impact

Successful exploitation of CVE-2025-68670 allows an unauthenticated attacker to execute arbitrary code on the target system running a vulnerable version of xrdp. This could lead to complete system compromise, including data theft, malware installation, or denial of service. The vulnerability is particularly critical because it is pre-authentication, meaning no valid credentials are required to exploit it. While the exact number of victims is unknown, any system running a vulnerable xrdp version is at risk.

## Recommendation

*   Upgrade xrdp to version 0.10.5 or later, or to versions 0.9.27 or 0.10.4.1 with the backported patch to remediate CVE-2025-68670.
*   Apply the "Detect CVE-2025-68670 Exploitation Attempt via Long Domain" Sigma rule to identify potential exploitation attempts by detecting abnormally long domain names starting with an underscore in RDP traffic.
*   Apply the "Detect CVE-2025-68670 Exploitation Attempt via process creation" Sigma rule to identify potential exploitation attempts by detecting process creations originating from xrdp processes.
*   Monitor network traffic for RDP connections with unusually long domain names in the client info packets, as this may indicate an attempted exploit.
