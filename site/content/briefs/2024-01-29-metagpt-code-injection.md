---
title: FoundationAgents MetaGPT Code Injection Vulnerability (CVE-2026-5971)
slug: 2024-01-29-metagpt-code-injection
description: A code injection vulnerability exists in FoundationAgents MetaGPT <= 0.8.1 within the ActionNode.xml_fill function, allowing remote attackers to inject code due to improper neutralization of directives in dynamically evaluated code.
date: "2026-04-09T18:17:04Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - code-injection
  - vulnerability
  - metagpt
  - CVE-2026-5971
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5971
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5971
rules:
  - title: Detect MetaGPT XML Injection Attempt
    description: Detects potential XML injection attempts against MetaGPT by monitoring for suspicious patterns in HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect MetaGPT Suspicious Child Processes
    description: Detects suspicious child processes spawned by MetaGPT, indicating potential post-exploitation activity.
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

A code injection vulnerability, identified as CVE-2026-5971, has been discovered in FoundationAgents MetaGPT versions up to 0.8.1. The vulnerability resides in the `ActionNode.xml_fill` function within the `metagpt/actions/action_node.py` file, specifically related to the XML Handler component. This flaw allows a remote attacker to inject malicious code by exploiting improper neutralization of directives in dynamically evaluated code. A proof-of-concept exploit is publicly available, increasing the likelihood of exploitation. The project maintainers were notified of the vulnerability via a pull request but have not yet addressed the issue. This poses a significant risk to systems using vulnerable versions of MetaGPT, especially those exposed to untrusted input.

## Attack Chain

1. An attacker identifies a MetaGPT instance running a vulnerable version (<= 0.8.1).
2. The attacker crafts malicious XML input designed to exploit the `ActionNode.xml_fill` function.
3. The attacker sends the malicious XML to the MetaGPT instance through a network request, likely via an API endpoint.
4. The `ActionNode.xml_fill` function processes the malicious XML, failing to properly neutralize directives.
5. The injected code is dynamically evaluated within the MetaGPT environment.
6. The attacker gains arbitrary code execution within the MetaGPT process, potentially escalating privileges.
7. The attacker leverages the code execution to compromise the system, potentially gaining access to sensitive data.
8. The attacker exfiltrates sensitive data or causes other damage based on their objectives.

## Impact

Successful exploitation of CVE-2026-5971 can lead to arbitrary code execution on systems running vulnerable versions of FoundationAgents MetaGPT (<= 0.8.1). This could allow attackers to steal sensitive information, modify system configurations, install malware, or disrupt services. The availability of a public exploit increases the likelihood of widespread attacks targeting vulnerable systems. The specific number of potential victims and targeted sectors are currently unknown, but any system running MetaGPT and processing potentially malicious XML input is at risk.

## Recommendation

*   Apply any available patches or updates for FoundationAgents MetaGPT to address CVE-2026-5971 as soon as they are released.
*   Implement input validation and sanitization measures to prevent malicious XML from being processed by the `ActionNode.xml_fill` function.
*   Monitor web server logs for suspicious activity related to XML processing, such as unusual requests or errors. Deploy the Sigma rule `Detect MetaGPT XML Injection Attempt` to identify potential exploit attempts based on HTTP request characteristics.
*   Enable process monitoring to detect suspicious processes spawned by MetaGPT, especially those with network connections. Deploy the Sigma rule `Detect MetaGPT Suspicious Child Processes` to identify potential post-exploitation activity.
