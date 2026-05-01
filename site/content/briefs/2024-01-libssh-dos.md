---
title: Libssh Denial-of-Service Vulnerability via Inefficient Regular Expression Processing (CVE-2026-0967)
slug: 2024-01-libssh-dos
description: CVE-2026-0967 is a denial-of-service vulnerability in libssh, stemming from inefficient regular expression processing that could lead to defense evasion and impact availability on affected systems.
date: "2026-05-01T07:16:39Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - libssh
  - CVE-2026-0967
  - defense-evasion
vendors:
  - Microsoft
products:
  - libssh
affected_os:
  - linux
  - windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-0967
    cvss: 5.5
    epss: 0.0003
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-0967
rules:
  - title: Detect Suspicious Libssh Regex Processing
    description: Detects potential denial-of-service attempts against libssh by monitoring for high CPU usage by processes linked to libssh libraries.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect Abnormal Network Traffic to SSH Ports After Libssh Update
    description: This rule detects unusual network activity to standard SSH ports (22, 2222) after the libssh library has been updated, potentially indicating attempts to exploit vulnerabilities.
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1068
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

CVE-2026-0967 is a denial-of-service (DoS) vulnerability affecting libssh, a library implementing the SSH protocol. The root cause lies in the inefficient processing of regular expressions within the library's code. An attacker could exploit this vulnerability by sending specially crafted input that triggers excessive resource consumption during regular expression matching, leading to a denial of service. Successful exploitation could potentially enable defense evasion by overwhelming security controls and negatively impacting the availability of systems relying on the vulnerable libssh library. The vulnerability affects both Linux and Windows platforms where libssh is used.

## Attack Chain

1.  The attacker identifies a service or application utilizing a vulnerable version of libssh.
2.  The attacker crafts a malicious input string designed to trigger inefficient regular expression processing within libssh.
3.  The attacker sends the crafted input to the vulnerable service via a network connection (e.g., SSH).
4.  The libssh library attempts to process the malicious input using its regular expression engine.
5.  The inefficient regular expression causes excessive CPU consumption or memory allocation.
6.  The vulnerable service becomes unresponsive due to resource exhaustion, leading to a denial-of-service condition.
7.  Subsequent legitimate requests to the service are blocked or delayed, further exacerbating the impact.

## Impact

Successful exploitation of CVE-2026-0967 can result in a denial-of-service condition, rendering affected services or applications unavailable. The impact scope depends on the role of the affected system. For example, a critical server becoming unavailable could disrupt business operations. While the number of potential victims is unknown, any system utilizing a vulnerable version of libssh is susceptible. The defense evasion aspect could allow attackers to bypass security controls during the DoS.

## Recommendation

*   Identify systems using libssh and determine the installed version.
*   Apply available patches or updates for libssh to remediate CVE-2026-0967 as released by Microsoft.
*   Deploy the Sigma rule "Detect Suspicious Libssh Regex Processing" to monitor for potential exploitation attempts.
*   Monitor CPU and memory usage on systems running libssh for unusual spikes, which may indicate a DoS attack.
*   Implement rate limiting on services using libssh to mitigate the impact of DoS attacks.
