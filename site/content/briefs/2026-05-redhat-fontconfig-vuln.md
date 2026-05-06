---
title: Red Hat Hardened Images RPMs Fontconfig Vulnerability
slug: 2026-05-redhat-fontconfig-vuln
description: A local attacker can exploit a vulnerability in Red Hat Hardened Images RPMs to execute arbitrary code or cause a denial of service.
date: "2026-05-06T10:30:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - code-execution
  - denial-of-service
  - linux
vendors:
  - Red Hat
products:
  - Hardened Images RPMs (fontconfig)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1365
rules:
  - title: Detect Suspicious Font Configuration File Creation
    description: Detects the creation of font configuration files in user directories, which could indicate malicious activity.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
  - title: Detect Application Crashes Potentially Related to Fontconfig
    description: Detects application crashes that might be related to fontconfig parsing errors.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A vulnerability exists in Red Hat Hardened Images RPMs related to the fontconfig package. A local attacker can exploit this vulnerability to achieve arbitrary code execution or trigger a denial-of-service condition. The specific details of the vulnerability are not provided in the source, but the potential impact necessitates immediate attention. This vulnerability affects systems utilizing Red Hat's Hardened Images RPMs and could lead to compromise of sensitive data or system instability.

## Attack Chain

1.  Attacker gains local access to a system running Red Hat Hardened Images RPMs.
2.  Attacker crafts a malicious font configuration file leveraging the fontconfig vulnerability.
3.  Attacker places the malicious font configuration file in a location accessible to the fontconfig library (e.g., user-specific font directory).
4.  An application using fontconfig attempts to load the malicious font configuration file.
5.  The vulnerability in fontconfig is triggered during parsing of the malicious file.
6.  This leads to arbitrary code execution within the context of the application using fontconfig.
7.  Alternatively, the vulnerability may lead to a denial-of-service condition if the parsing error crashes the application.

## Impact

Successful exploitation of this vulnerability could allow a local attacker to execute arbitrary code with the privileges of the application using fontconfig. This can result in a full system compromise if the affected application runs with elevated privileges. A denial-of-service condition can also be triggered, impacting system availability. The number of victims and specific sectors targeted are unknown, but any system using the vulnerable Red Hat Hardened Images RPMs is potentially at risk.

## Recommendation

*   Apply available patches or updates from Red Hat for the Hardened Images RPMs to remediate the fontconfig vulnerability.
*   Monitor for suspicious file creations in font configuration directories using the `file_event` Sigma rule.
*   Investigate any application crashes that may be related to fontconfig parsing errors.
