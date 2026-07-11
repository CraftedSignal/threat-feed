---
title: 'CVE-2026-59869: js-yaml Vulnerability Leading to Quadratic CPU Consumption and DoS'
slug: 2026-07-js-yaml-quadratic-cpu-dos
description: A vulnerability, CVE-2026-59869, in the `js-yaml` library allows attackers to craft malicious YAML merge-key chains, which can lead to quadratic CPU consumption and a Denial of Service condition in applications processing the input.
date: "2026-07-11T07:42:35Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
tags:
  - denial-of-service
  - vulnerability
  - yaml
products:
  - js-yaml
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: The vulnerability ... can lead to quadratic CPU consumption, potentially causing a Denial of Service condition
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: can be exploited through specially crafted YAML merge-key chains. This can lead to quadratic CPU consumption
    confidence_band: high
cves:
  - id: CVE-2026-59869
    cvss: 7.5
    epss: 0.0035
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-59869
---

CVE-2026-59869 describes a vulnerability in the `js-yaml` library, an open-source YAML parser for JavaScript, that can be triggered by specially crafted YAML merge-key chains. This flaw can cause the library to enter a state of quadratic CPU consumption, where processing time escalates disproportionately with the input size. The vulnerability, reported by the Microsoft Security Response Center (MSRC), poses a significant risk to applications that rely on `js-yaml` to parse untrusted or externally provided YAML data. Successful exploitation can result in a Denial of Service (DoS) against the affected application, making it unresponsive and unavailable to legitimate users. While specific targeting campaigns or in-the-wild exploitation have not been detailed, the nature of the vulnerability suggests it could be leveraged by attackers seeking to disrupt services.

## Attack Chain

1. An attacker crafts a malicious YAML document containing deeply nested or excessively recursive merge-key chains.
2. The attacker delivers this crafted YAML document to a target application that uses the `js-yaml` library for parsing.
3. The application receives and attempts to parse the malicious YAML input using the `js-yaml` library.
4. During the parsing process, `js-yaml` encounters the specially designed merge-key chains.
5. The library's algorithm for resolving these chains exhibits quadratic complexity, causing its CPU utilization to rapidly increase.
6. The application experiences significant resource exhaustion due to the `js-yaml` parsing operation consuming excessive CPU cycles.
7. The application becomes unresponsive or crashes, resulting in a Denial of Service condition for users.

## Impact

Successful exploitation of CVE-2026-59869 leads directly to a Denial of Service (DoS) condition in any application that uses the vulnerable `js-yaml` library to process untrusted YAML input. This can cause critical applications to become unresponsive, disrupting business operations, leading to financial losses, and damaging reputation. The quadratic nature of the CPU consumption means that even relatively small malicious inputs could significantly impact server resources, making the affected system unavailable until the process is terminated or the vulnerability is remediated. The scope of potential victims includes any organization deploying applications that depend on `js-yaml` and expose YAML parsing functionality to external input.

## Recommendation

* Patch or update the `js-yaml` library to a non-vulnerable version to remediate CVE-2026-59869 as soon as updates are available.
* Implement input validation and sanitization for all YAML data processed by applications, especially from untrusted sources, to mitigate the risk of crafted merge-key chains.
* Monitor application performance metrics, particularly CPU utilization, for sudden and sustained spikes following the processing of external YAML inputs to detect potential DoS attacks.
