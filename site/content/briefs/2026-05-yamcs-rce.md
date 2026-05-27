---
title: Yamcs Remote Code Execution via Mission Database Algorithm Override
slug: 2026-05-yamcs-rce
description: Yamcs is vulnerable to remote code execution (RCE) due to the Nashorn ScriptEngine being constructed without a ClassFilter, allowing a user with the ChangeMissionDatabase privilege to execute arbitrary Java code on the Yamcs server, affecting releases from 4.7.3 through 5.12.6 and current master.
date: "2026-05-27T22:46:24Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - yamcs
  - rce
  - injection
vendors:
  - Yamcs
products:
  - yamcs-core
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-vmwp-vh32-rj75
  - CVE-2026-46562
rules:
  - title: Detect Yamcs Algorithm Override RCE Attempt
    description: Detects CVE-2026-46562 exploitation — attempts to inject shell commands via Nashorn engine eval in Yamcs algorithm override
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
  - title: Detect Yamcs Algorithm Override Event Log Tampering
    description: Detects CVE-2026-46562 exploitation - Suppression of expected algorithm override events after modification
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - application
      - yamcs
rules_count: 2
---

Yamcs, a mission control system, is vulnerable to remote code execution due to the insecure instantiation of the Nashorn `ScriptEngine`. Specifically, the `ScriptAlgorithmExecutorFactory` constructs the engine used to evaluate user-supplied algorithm text in `MdbOverrideApi.updateAlgorithm` without a `ClassFilter`. This oversight allows an attacker with the `ChangeMissionDatabase` privilege (or, in default configurations, no authentication) to execute arbitrary Java code on the Yamcs server. The vulnerability exists because attacker-supplied JavaScript can reach any Java class via `Java.type(...)`, enabling execution of OS commands within the Yamcs JVM. The affected versions span from `4.7.3` (released 2018-11-22) through `5.12.6` and include the current `master` branch, making a large number of deployments vulnerable.

## Attack Chain

1.  An attacker sends a PATCH request to the `/api/mdb-overrides/{instance}/{processor}/algorithms/{name}` endpoint.
2.  The `MdbOverrideApi.updateAlgorithm` method receives the request.
3.  `AlgorithmManager.overrideAlgorithm` is called with the attacker-supplied algorithm text.
4.  `ScriptAlgorithmExecutorFactory.makeExecutor` creates a Nashorn `ScriptEngine` *without* a `ClassFilter`.
5.  The attacker-supplied JavaScript code is passed to `scriptEngine.eval(functionScript)`.
6.  The attacker uses `Java.type("java.lang.Runtime").getRuntime().exec(...)` to execute arbitrary OS commands.
7.  The command runs as the user running the Yamcs server.
8.  The attacker gains control of the Yamcs server and potentially other systems reachable from it, enabling mission disruption or data exfiltration.

## Impact

Successful exploitation allows an attacker to execute arbitrary code as the user running the Yamcs server, leading to a full compromise of the system. This can result in forged telecommands, suppressed alarms, tampered telemetry data, unauthorized access to sensitive files (including cryptographic keys and credentials), and potential pivoting to other ground-station systems. For a Yamcs deployment managing spacecraft operations, the impact could involve disruption or seizure of control of the mission, as well as installation of persistent backdoors. All Yamcs deployments running in the default configuration (no `security.yaml` present) are vulnerable to unauthenticated network attackers.

## Recommendation

*   Deploy the Sigma rule `Detect Yamcs Algorithm Override RCE Attempt` to your SIEM and tune for your environment to detect attempts to exploit CVE-2026-46562.
*   Enable authentication and restrict the `ChangeMissionDatabase` privilege only to trusted users to mitigate the risk of internal exploitation.
*   Apply a patch that adds a `ClassFilter` to the Nashorn `ScriptEngine` to prevent arbitrary Java class access.
*   Monitor the Yamcs event stream for `WARNING` events from `ScriptAlgorithmExecutorFactory.java:112` and `CRITICAL` events from `AlgorithmManager.java:546` to detect failed exploitation attempts.
