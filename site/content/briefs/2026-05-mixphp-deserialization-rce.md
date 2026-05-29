---
title: MixPHP Framework 2.2.17 Unsafe Deserialization Remote Code Execution
slug: 2026-05-mixphp-deserialization-rce
description: MixPHP Framework 2.2.17 is vulnerable to remote code execution due to unsafe deserialization, with a public exploit available, increasing the risk for unpatched systems.
date: "2026-05-29T07:52:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - webapps
  - rce
  - deserialization
vendors:
  - MixPHP
products:
  - MixPHP Framework 2.2.17
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://www.exploit-db.com/exploits/52590
rules:
  - title: Detect MixPHP Unsafe Deserialization RCE Attempt via POST Request
    description: Detects a POST request to a MixPHP application with suspicious serialized data indicative of CVE-related exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - webserver
  - title: Detect PHP file creation after possible deserialization attack
    description: Detects creation of php files in web directories after possible deserialization attack
    platform: sigma
    severity: medium
    tactics:
      - persistence
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A remote code execution vulnerability due to unsafe deserialization has been identified in MixPHP Framework version 2.2.17. A public exploit, EDB-52590, has been published on Exploit-DB, significantly increasing the risk for unpatched systems. The vulnerability allows an attacker to execute arbitrary code on the server by exploiting the unsafe handling of deserialized data. This is particularly critical as the availability of a working exploit makes exploitation easier and more likely.

## Attack Chain

1. An attacker identifies a MixPHP Framework 2.2.17 instance.
2. The attacker locates a deserialization entry point within the application, such as a function or API endpoint that accepts serialized data.
3. The attacker crafts a malicious serialized object containing a payload designed to execute arbitrary code.
4. The malicious serialized object is sent to the deserialization entry point via HTTP request.
5. The MixPHP application attempts to deserialize the object.
6. Due to the unsafe deserialization vulnerability, the malicious payload within the object is executed.
7. The attacker gains remote code execution on the server.
8. The attacker can then perform further actions such as installing malware, exfiltrating data, or pivoting to other systems.

## Impact

Successful exploitation allows attackers to execute arbitrary code on the affected server. This can lead to complete system compromise, data theft, denial of service, or further propagation of attacks to other systems within the network. The availability of a public exploit means that less skilled attackers can easily leverage this vulnerability.

## Recommendation

- Upgrade MixPHP Framework to a patched version that addresses the unsafe deserialization vulnerability.
- Monitor web server logs for suspicious POST requests containing serialized data to identify potential exploitation attempts. Deploy the Sigma rules provided to detect exploitation attempts.
- Implement input validation and sanitization to prevent malicious data from being processed by the application.
