---
title: MetaGPT Code Injection Vulnerability (CVE-2026-6110)
slug: 2026-04-metagpt-code-injection
description: A code injection vulnerability exists in FoundationAgents MetaGPT up to version 0.8.1, specifically affecting the generate_thoughts function in the metagpt/strategy/tot.py file of the Tree-of-Thought Solver component, allowing for remote exploitation with a publicly available exploit.
date: "2026-04-12T03:16:08Z"
severities:
  - high
tags:
  - code-injection
  - metagpt
  - cve-2026-6110
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
cves:
  - id: CVE-2026-6110
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6110
  - https://github.com/FoundationAgents/MetaGPT/
  - https://github.com/FoundationAgents/MetaGPT/issues/1933
  - https://github.com/FoundationAgents/MetaGPT/pull/1946
  - https://vuldb.com/submit/791761
  - https://vuldb.com/vuln/356970
  - https://vuldb.com/vuln/356970/cti
rules:
  - title: Detect MetaGPT Code Injection Attempt
    description: Detects potential code injection attempts targeting the MetaGPT application through suspicious HTTP requests to the generate_thoughts function.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - webserver
      - linux
  - title: Detect MetaGPT Code Injection - Metagpt directory
    description: Detects potential code injection attempts by looking at the file path
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A code injection vulnerability, identified as CVE-2026-6110, affects FoundationAgents MetaGPT versions up to 0.8.1. The vulnerability resides in the `generate_thoughts` function within the `metagpt/strategy/tot.py` file, a part of the Tree-of-Thought Solver. This flaw enables attackers to inject arbitrary code and execute it within the context of the MetaGPT application. The vulnerability is remotely exploitable and a proof-of-concept exploit is publicly available, increasing the risk of widespread exploitation. The MetaGPT project has been notified of this issue through an issue report, but there has been no response at the time of this writing. This vulnerability poses a significant threat to systems running vulnerable MetaGPT instances, as successful exploitation could lead to arbitrary code execution, potentially compromising the confidentiality, integrity, and availability of the system and its data.

## Attack Chain

1.  The attacker identifies a vulnerable MetaGPT instance running version 0.8.1 or earlier.
2.  The attacker crafts a malicious input designed to exploit the code injection vulnerability in the `generate_thoughts` function of `metagpt/strategy/tot.py`.
3.  The attacker sends the malicious input to the vulnerable `generate_thoughts` function. This could occur via a network request to an API endpoint that utilizes the vulnerable function.
4.  The `generate_thoughts` function fails to properly sanitize or validate the input, allowing the injected code to be processed as part of the application logic.
5.  The injected code is executed within the context of the MetaGPT application, potentially gaining access to sensitive data, resources, or system functionalities.
6.  The attacker leverages the code execution to escalate privileges or move laterally within the compromised system.
7.  The attacker installs a persistent backdoor for future access or further compromise.
8.  The attacker achieves their final objective, such as data exfiltration, denial of service, or further exploitation of the compromised environment.

## Impact

Successful exploitation of CVE-2026-6110 can lead to arbitrary code execution on the affected MetaGPT instance. This could allow an attacker to gain complete control over the system, potentially leading to data breaches, service disruptions, or further attacks on internal networks. Given the nature of MetaGPT as an AI-driven tool, the compromise could extend to manipulation of generated content or models. While specific victim counts are unavailable, the availability of a public exploit increases the likelihood of widespread exploitation targeting organizations and individuals using the affected MetaGPT versions.

## Recommendation

*   Upgrade FoundationAgents MetaGPT to a patched version that addresses CVE-2026-6110. Check the MetaGPT GitHub repository for updates.
*   Apply input validation and sanitization to the `generate_thoughts` function in `metagpt/strategy/tot.py` to prevent code injection.
*   Monitor web server logs for suspicious requests targeting MetaGPT endpoints, specifically those interacting with the `generate_thoughts` function (reference the overview section for file path).
*   Deploy the Sigma rule "Detect MetaGPT Code Injection Attempt" to identify potential exploitation attempts based on suspicious HTTP requests (reference the rule below).
*   Enable web server logging to capture HTTP request details, which are essential for the effective operation of the Sigma rule (logsource: webserver).
