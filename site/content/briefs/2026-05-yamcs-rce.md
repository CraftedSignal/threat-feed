---
title: Yamcs Authenticated Remote Code Execution via Jython Algorithm Code Injection
slug: 2026-05-yamcs-rce
description: Yamcs is vulnerable to authenticated remote code execution (CVE-2026-46621) where an authenticated user with the ChangeMissionDatabase privilege can inject malicious Jython code into existing Python algorithms, leading to arbitrary command execution on the underlying host operating system.
date: "2026-05-27T22:53:33Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - rce
  - code-injection
  - yamcs
vendors:
  - Yamcs
products:
  - yamcs-core (< 5.12.7)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-2g95-6x5q-xjwj
iocs:
  - type: url
    value: https://<YOUR-WEBHOOK-URL>/RCE
ioc_counts:
  url: 1
rules:
  - title: Detect Yamcs Jython Code Injection
    description: Detects CVE-2026-46621 exploitation — Malicious Jython code injection attempts in Yamcs via the MDB API endpoint.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.006
    data_sources:
      - webserver
  - title: Detect Yamcs Algorithm Modification via API
    description: Detects Yamcs algorithm modifications via the API, which could indicate malicious activity following CVE-2026-46621.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1546.003
    data_sources:
      - webserver
rules_count: 2
---

Yamcs is vulnerable to a server-side code injection vulnerability (CVE-2026-46621) in its script evaluation engine for Python algorithms. The application dynamically compiles and evaluates user-controlled algorithm text using Jython via the JSR-223 ScriptEngine API without a secure sandbox. This vulnerability impacts Yamcs deployments where users have the `ChangeMissionDatabase` privilege and a scripting engine like Jython is present. An authenticated user can exploit this by overriding the algorithm logic via the REST API at `/api/mdb/{instance}/realtime/algorithms/{name}`. The vulnerability affects `yamcs-core` versions prior to 5.12.7. This allows an attacker to escalate from application-level configuration privileges to full System/OS control, leading to arbitrary command execution, data exfiltration, and lateral movement.

## Attack Chain

1. An attacker authenticates to the Yamcs application with an account possessing the `ChangeMissionDatabase` privilege.
2. The attacker identifies an existing algorithm defined in the Mission Database (MDB) with its language explicitly set to `python`.
3. The attacker crafts a malicious payload containing Jython code that leverages `java.lang.Runtime` to execute arbitrary OS commands.
4. The attacker sends an HTTP PATCH request to `/api/mdb/{instance}/realtime/algorithms/{name}` to inject the malicious code into the identified Python algorithm.
5. The Yamcs server receives the PATCH request and updates the algorithm's text with the provided malicious code.
6. The Yamcs server compiles the injected Jython code into an executable script on the fly.
7. The attacker triggers the evaluation of the modified algorithm, potentially by sending telemetry data that the algorithm depends on.
8. The injected Jython code executes the attacker-controlled OS command, achieving remote code execution on the host system.

## Impact

This vulnerability impacts Yamcs deployments where users have the `ChangeMissionDatabase` privilege. An attacker can leverage this to escalate from application-level configuration privileges to full System/OS control, leading to arbitrary command execution. This can result in data exfiltration, and potential lateral movement within the hosting infrastructure.

## Recommendation

*   Upgrade Yamcs to version 5.12.7 or later to patch CVE-2026-46621.
*   Review and restrict the privileges granted to users, especially the `ChangeMissionDatabase` privilege, to minimize the attack surface.
*   Deploy the Sigma rule "Detect Yamcs Jython Code Injection" to monitor for attempts to inject malicious Jython code into algorithms.
*   Monitor network traffic for connections to attacker-controlled webhooks or other suspicious destinations, such as the URL listed in the IOC table.
