---
title: Red Hat Enterprise Linux libxslt Vulnerability Allows DoS and Code Execution
slug: 2024-05-rhel-libxslt-vuln
description: A local attacker can exploit a vulnerability in libxslt on Red Hat Enterprise Linux to cause a denial of service or execute arbitrary program code.
date: "2026-04-01T09:20:35Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - libxslt
  - rhel
  - vulnerability
  - code-execution
  - denial-of-service
  - linux
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-0718
rules:
  - title: Detect Suspicious Child Processes from Libxslt
    description: Detects suspicious child processes spawned by applications utilizing the libxslt library, which could indicate code execution following exploitation of a vulnerability.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Execution of Scripts in /tmp by Unlikely Programs
    description: Detects the execution of scripts in /tmp by programs other than those typically used to execute scripts. This could be caused by code-execution after an exploit.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A vulnerability exists in the libxslt library within Red Hat Enterprise Linux (RHEL) that could allow a local attacker to perform a denial-of-service (DoS) attack or execute arbitrary code. While specific versions and CVEs are not mentioned in the advisory, the potential impact is significant. This vulnerability could be exploited if a user processes a malicious XSLT stylesheet, leading to memory corruption or other exploitable conditions. This poses a serious risk to systems where libxslt is used to process untrusted or user-supplied XSLT files, potentially allowing for complete system compromise. Defenders should prioritize identifying vulnerable systems and applying patches as soon as they become available.

## Attack Chain

1.  A local attacker gains access to the target RHEL system.
2.  The attacker crafts a malicious XSLT stylesheet designed to exploit the libxslt vulnerability.
3.  The attacker leverages a local program that uses libxslt to parse the crafted stylesheet. This could be a custom application or a common utility that relies on libxslt for XSLT processing.
4.  When the vulnerable libxslt library parses the malicious stylesheet, it triggers a buffer overflow or other memory corruption vulnerability.
5.  The memory corruption allows the attacker to overwrite critical system memory or inject malicious code.
6.  If a DoS condition is triggered, the affected service or application crashes, leading to a disruption of service.
7.  If the attacker successfully injects and executes arbitrary code, they gain control of the affected process with the privileges of the user running the application.
8.  The attacker can then leverage their gained access to escalate privileges and perform further malicious activities on the system, such as installing backdoors or exfiltrating sensitive data.

## Impact

Successful exploitation of this vulnerability can lead to a denial-of-service condition, causing the affected application or service to crash and become unavailable. More critically, it can allow a local attacker to execute arbitrary code with the privileges of the user running the vulnerable application. This could lead to full system compromise if the affected application runs with elevated privileges. The impact is amplified in environments where libxslt is used to process untrusted or user-supplied XSLT files.

## Recommendation

*   Identify all systems running Red Hat Enterprise Linux that utilize the libxslt library.
*   Monitor process creations for suspicious child processes spawned by applications utilizing libxslt with the provided Sigma rules.
*   When available, apply the appropriate patches or updates for libxslt provided by Red Hat to remediate the vulnerability.
*   Implement strict input validation and sanitization for XSLT stylesheets processed by applications to mitigate the risk of exploitation.
