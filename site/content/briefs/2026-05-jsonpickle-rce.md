---
title: jsonpickle 2.0.0 Remote Code Execution via Deserialization of Malicious Payloads
slug: 2026-05-jsonpickle-rce
description: jsonpickle version 2.0.0 contains a remote code execution vulnerability, allowing attackers to execute arbitrary Python commands by deserializing malicious JSON payloads containing py/repr objects, which invoke the eval function.
date: "2026-05-16T16:17:25Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - deserialization
  - remote code execution
  - cve-2021-47952
vendors:
  - jsonpickle
products:
  - jsonpickle 2.0.0
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1566
    technique_name: Phishing
cves:
  - id: CVE-2021-47952
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-47952
  - https://github.com/jsonpickle/jsonpickle
  - https://jsonpickle.github.io
  - https://www.exploit-db.com/exploits/49585
  - https://www.vulncheck.com/advisories/python-jsonpickle-remote-code-execution-via-py-repr
rules:
  - title: Detect jsonpickle RCE via py/repr object
    description: Detects CVE-2021-47952 exploitation -- deserialization of JSON with a py/repr object, indicating a potential RCE attempt via jsonpickle.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1566.001
    data_sources:
      - webserver
  - title: Detect jsonpickle RCE via eval function call in logs
    description: Detects CVE-2021-47952 exploitation -- logs indicating a Python eval function call originating from jsonpickle deserialization context.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1566.001
    data_sources:
      - application
rules_count: 2
---

jsonpickle version 2.0.0 is vulnerable to remote code execution. This vulnerability allows attackers to execute arbitrary Python commands by deserializing malicious JSON payloads that include `py/repr` objects. Attackers exploit this flaw by crafting JSON strings with `py/repr` directives that, when deserialized, invoke the `eval` function. This enables the execution of system commands and arbitrary code on systems that process these malicious JSON payloads. The vulnerability was published May 16th, 2026, and defenders should prioritize detection of malicious deserialization attempts.

## Attack Chain

1. An attacker crafts a malicious JSON payload containing a `py/repr` object.
2. The `py/repr` object contains a Python expression designed for code execution.
3. The attacker sends the malicious JSON payload to a vulnerable application using jsonpickle 2.0.0.
4. The application uses jsonpickle's `decode` function to deserialize the JSON payload.
5. During deserialization, the `py/repr` directive is processed.
6. The `eval` function is invoked with the Python expression from the `py/repr` object.
7. The Python expression executes arbitrary code or commands on the server.
8. The attacker achieves remote code execution, potentially leading to full system compromise.

## Impact

Successful exploitation of CVE-2021-47952 can lead to complete system compromise. Attackers can execute arbitrary code, potentially leading to data theft, system takeover, or denial of service. Given the critical CVSS score of 9.8, organizations using jsonpickle 2.0.0 are at high risk.

## Recommendation

*   Upgrade to a patched version of jsonpickle if available.
*   Deploy the Sigma rule "Detect jsonpickle RCE via py/repr object" to detect deserialization attempts.
*   Monitor application logs for errors related to JSON deserialization.
*   Implement input validation to sanitize JSON payloads before deserialization.
*   Consult the VulnCheck advisory for additional context on exploitation vectors.
