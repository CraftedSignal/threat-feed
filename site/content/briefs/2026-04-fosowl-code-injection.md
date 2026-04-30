---
title: Fosowl agenticSeek 0.1.0 Code Injection Vulnerability (CVE-2026-5584)
slug: 2026-04-fosowl-code-injection
description: A code injection vulnerability (CVE-2026-5584) exists in Fosowl agenticSeek 0.1.0, allowing remote attackers to execute arbitrary code by manipulating the query endpoint through the PyInterpreter.execute function.
date: "2026-04-05T17:16:57Z"
severities:
  - critical
exploited: true
type: threat
types:
  - threat
tags:
  - code-injection
  - vulnerability
  - fosowl
  - cve-2026-5584
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
cves:
  - id: CVE-2026-5584
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5584
rules:
  - title: Detect Fosowl agenticSeek Code Injection Attempt
    description: Detects potential code injection attempts targeting the query endpoint in Fosowl agenticSeek 0.1.0
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - webserver
      - linux
  - title: Detect Fosowl agenticSeek Code Injection Attempt - POST
    description: Detects potential code injection attempts targeting the query endpoint in Fosowl agenticSeek 0.1.0 (POST method)
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Fosowl agenticSeek version 0.1.0 is vulnerable to code injection (CVE-2026-5584). The vulnerability lies within the `PyInterpreter.execute` function in the `sources/tools/PyInterpreter.py` file, specifically related to the query endpoint. An unauthenticated attacker can exploit this flaw to inject and execute arbitrary code remotely. The vulnerability was reported to the vendor, but they did not respond, and a public exploit is available, increasing the risk of active exploitation. This poses a significant threat because successful exploitation allows for complete system compromise.

## Attack Chain

1.  The attacker identifies a vulnerable instance of Fosowl agenticSeek 0.1.0.
2.  The attacker crafts a malicious request targeting the query endpoint.
3.  The crafted request includes a payload designed to exploit the `PyInterpreter.execute` function.
4.  The `PyInterpreter.execute` function processes the malicious payload without proper sanitization.
5.  The unsanitized payload is executed as code by the Python interpreter.
6.  The attacker gains arbitrary code execution on the server hosting Fosowl agenticSeek.
7.  The attacker escalates privileges, potentially gaining root access.
8.  The attacker installs malware, exfiltrates data, or performs other malicious actions.

## Impact

Successful exploitation of CVE-2026-5584 allows a remote attacker to execute arbitrary code on the affected system. This can lead to complete system compromise, data theft, or denial-of-service. Given the availability of a public exploit, unpatched systems are at high risk of being targeted. The specific number of potential victims and targeted sectors are currently unknown.

## Recommendation

*   Upgrade Fosowl agenticSeek to a patched version if available.
*   Implement input validation and sanitization on the query endpoint to prevent code injection.
*   Deploy the Sigma rule `Detect Fosowl agenticSeek Code Injection Attempt` to identify exploitation attempts.
*   Monitor web server logs for suspicious requests targeting the query endpoint (`webserver` log source).
