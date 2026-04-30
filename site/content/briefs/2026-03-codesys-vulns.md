---
title: CODESYS Multiple Vulnerabilities Allow Arbitrary Code Execution and DoS
slug: 2026-03-codesys-vulns
description: Multiple vulnerabilities in CODESYS allow a remote attacker to execute arbitrary program code and conduct a denial-of-service attack.
date: "2026-03-25T09:46:08Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - codesys
  - vulnerability
  - arbitrary-code-execution
  - denial-of-service
  - ics
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0832
rules:
  - title: Suspicious Process Connecting to CODESYS Ports
    description: Detects unusual processes establishing network connections to common CODESYS ports.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Unexpected Process Creation Under CODESYS Directory
    description: Detects creation of new processes under the CODESYS installation directory which might indicate malicious activity
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Multiple vulnerabilities have been identified in CODESYS, a software platform widely used for industrial automation. These vulnerabilities, if exploited, could allow a remote attacker to execute arbitrary program code on affected systems and/or cause a denial-of-service (DoS) condition. Given the prevalence of CODESYS in critical infrastructure and manufacturing environments, these vulnerabilities pose a significant risk. Public details are limited, but the potential impact necessitates immediate action from defenders to identify and mitigate potentially vulnerable CODESYS installations. Successful exploitation can lead to significant disruption of industrial processes, data manipulation, and potentially physical damage depending on the affected systems.

## Attack Chain

1.  Attacker identifies a vulnerable CODESYS installation accessible over the network (e.g., via Shodan or similar).
2.  Attacker crafts a malicious request specifically targeting one of the CODESYS vulnerabilities. Due to lack of specifics, this step is generic. Example attack vectors could include crafted network packets or malicious project files.
3.  The malicious request is sent to the vulnerable CODESYS service.
4.  The CODESYS service improperly processes the request due to the vulnerability.
5.  This improper processing leads to arbitrary code execution within the context of the CODESYS service.
6.  The attacker executes malicious code to gain control of the CODESYS runtime. This code could install a backdoor, modify control logic, or exfiltrate data.
7.  Alternatively, the malformed request triggers a denial-of-service condition, causing the CODESYS service or the entire system to crash.
8.  The attacker disrupts industrial processes or gains unauthorized access to the industrial control system.

## Impact

Successful exploitation of these CODESYS vulnerabilities can have severe consequences, including unauthorized access to industrial control systems, disruption of critical infrastructure, data manipulation, and potentially physical damage. The number of affected systems is potentially large, given the widespread use of CODESYS in various sectors including manufacturing, energy, and transportation. A successful attack could lead to significant financial losses, reputational damage, and even safety risks.

## Recommendation

*   Monitor network traffic for suspicious activity targeting CODESYS services. Use the network connection rule below to detect unusual processes connecting to CODESYS ports.
*   Implement strict network segmentation to limit the exposure of CODESYS installations to external networks.
*   Since specific CVEs are not available, regularly check the CODESYS website for security updates and apply them immediately.
*   Investigate any crashes or unexpected behavior of CODESYS services, using process creation logs with the process creation rule below to see if the crash was caused by a malicious process.
