---
title: PromtEngineer localGPT LLM Prompt Handler Injection Vulnerability (CVE-2026-5002)
slug: 2024-01-02-localgpt-injection
description: A remote code injection vulnerability (CVE-2026-5002) exists in PromtEngineer localGPT versions up to commit 4d41c7d1713b16b216d8e062e51a5dd88b20b054, allowing attackers to execute arbitrary code by manipulating the LLM Prompt Handler component via the _route_using_overviews function in backend/server.py.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - injection
  - llm
  - localgpt
  - cve-2026-5002
  - webserver
vendors:
  - PromtEngineer
products:
  - localGPT
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5002
rules:
  - title: Detect Suspicious localGPT Requests
    description: Detects suspicious HTTP requests potentially exploiting the localGPT injection vulnerability (CVE-2026-5002).
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - webserver
      - linux
  - title: Detect localGPT Server File Modification
    description: Detects modification to the backend/server.py file in localGPT directory which could indicate an injection attempt.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-5002, has been identified in PromtEngineer localGPT, an open-source project providing local Large Language Model (LLM) capabilities. The vulnerability affects versions up to commit 4d41c7d1713b16b216d8e062e51a5dd88b20b054. The root cause lies within the `_route_using_overviews` function of the `backend/server.py` file, which is part of the LLM Prompt Handler component. Successful exploitation allows for remote code injection, granting attackers the ability to execute arbitrary commands on the server hosting localGPT. This is particularly concerning as localGPT is designed to handle user-provided prompts, making it a prime target for malicious actors. The vendor has not responded to disclosure attempts. The public availability of an exploit further elevates the risk.

## Attack Chain

1.  The attacker identifies an instance of PromtEngineer localGPT running a vulnerable version (<= 4d41c7d1713b16b216d8e062e51a5dd88b20b054).
2.  The attacker crafts a malicious prompt designed to exploit the injection vulnerability in the `_route_using_overviews` function.
3.  The attacker sends the malicious prompt to the localGPT instance through a network request, targeting the LLM Prompt Handler component.
4.  The `_route_using_overviews` function processes the malicious prompt without proper sanitization or validation.
5.  The lack of sanitization leads to the injection of attacker-controlled code into the LLM processing pipeline.
6.  The injected code is executed by the localGPT server, potentially allowing arbitrary command execution.
7.  The attacker gains control of the localGPT server, potentially escalating privileges.
8.  The attacker can now use the compromised server for further malicious activities, such as data exfiltration or lateral movement within the network.

## Impact

Successful exploitation of CVE-2026-5002 grants attackers the ability to execute arbitrary code on systems running vulnerable versions of PromtEngineer localGPT. This could lead to complete system compromise, data theft, and potential disruption of services. Given the nature of localGPT as a tool for handling sensitive information and prompts, the impact is significant. There is currently no information about specific victims or sectors targeted; however, the public availability of the exploit makes all deployments vulnerable.

## Recommendation

*   Apply any available patches or updates to PromtEngineer localGPT to mitigate CVE-2026-5002. Since version information is not disclosed, monitor the project's repository for any updates and apply them promptly.
*   Implement input validation and sanitization measures on the LLM Prompt Handler component to prevent code injection. Specifically, focus on the `_route_using_overviews` function in `backend/server.py`.
*   Deploy the Sigma rule "Detect Suspicious localGPT Requests" to identify potential exploitation attempts targeting CVE-2026-5002 based on HTTP request patterns.
*   Monitor network traffic for suspicious activity originating from systems running localGPT, looking for unusual outbound connections or data transfer patterns.
