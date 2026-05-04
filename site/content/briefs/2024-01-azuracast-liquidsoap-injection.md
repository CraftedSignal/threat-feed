---
title: AzuraCast Liquidsoap Code Injection in Remote Relay Password
slug: 2024-01-azuracast-liquidsoap-injection
description: AzuraCast is vulnerable to a Liquidsoap code injection vulnerability due to the incomplete migration from `cleanUpString()` to `toRawString()` in the remote relay password field, allowing a user with the `RemoteRelays` station permission to inject arbitrary Liquidsoap code by exploiting nested interpolation syntax, leading to arbitrary code execution, API key disclosure, and station disruption.
date: "2026-05-04T21:19:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azuracast
  - code-injection
  - liquidsoap
  - ghsa
vendors:
  - AzuraCast
products:
  - AzuraCast (<= 0.23.5)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-q4ph-8x8g-95f8
rules:
  - title: Detect AzuraCast Liquidsoap Code Injection via API
    description: Detects potential Liquidsoap code injection attempts in AzuraCast by monitoring PUT requests to the remote relay API endpoint containing nested Liquidsoap interpolation syntax.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect AzuraCast Liquidsoap Process Execution via Process Name
    description: Detects Liquidsoap process execution by monitoring for common Liquidsoap process names.
    platform: sigma
    severity: informational
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect AzuraCast Liquidsoap Configuration File Modification
    description: Detects modification of Liquidsoap configuration files. An attacker may write payloads to disk to achieve persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 3
---

AzuraCast versions 0.23.5 and earlier are vulnerable to a Liquidsoap code injection vulnerability in the remote relay password field. This flaw stems from an incomplete migration of user-controlled fields from the vulnerable `cleanUpString()` method to the safe `toRawString()` method. Specifically, while commit `ff49ef4` (dated 2026-03-06) addressed most fields, the remote relay password field continues to use `cleanUpString()`, which can be bypassed via nested Liquidsoap interpolation syntax (`#{#{EXPR}}`). An attacker with the `RemoteRelays` station permission can exploit this to inject arbitrary Liquidsoap code, potentially achieving remote code execution, disclosing internal API keys, reading and writing files within the Liquidsoap container, and disrupting station operation. This vulnerability allows attackers with minimal privileges to escalate their access within the AzuraCast environment.

## Attack Chain

1.  An attacker with `RemoteRelays` station permission crafts a malicious payload containing nested Liquidsoap interpolation syntax (`#{#{EXPR}}`).
2.  The attacker sends a `PUT` request to `/api/station/{station_id}/remote/{id}` to update the remote relay's password, including the crafted payload in the `source_password` field.
3.  The `mb_substr` function truncates the password to 100 characters, but the payload remains within this limit.
4.  The `ConfigWriter::getOutputString()` function calls the vulnerable `cleanUpString()` method on the password during station configuration regeneration.
5.  The `cleanUpString()` method's ungreedy regex fails to properly sanitize the nested interpolation, resulting in a bypass.
6.  The bypassed payload is embedded within a double-quoted string in the Liquidsoap configuration file.
7.  The Liquidsoap process loads the updated configuration file, triggering the evaluation of the injected Liquidsoap code.
8.  The attacker achieves arbitrary code execution within the Liquidsoap process container or gains access to sensitive information, such as the internal API key.

## Impact

Successful exploitation of this vulnerability can lead to severe consequences, including arbitrary code execution within the Liquidsoap process container, potentially compromising the entire AzuraCast installation. The disclosure of the internal API key grants the attacker full control over the station's API. Furthermore, the ability to read and write files within the Liquidsoap container allows for further exploitation and persistence. The attacker can also disrupt station operation by injecting malicious configurations that crash the Liquidsoap process. The low privilege requirement (only `RemoteRelays` permission) makes this vulnerability highly accessible to malicious actors.

## Recommendation

*   Immediately replace the `cleanUpString()` method with `toRawString()` for the remote relay password field in `ConfigWriter.php`, as described in the provided fix, to prevent Liquidsoap code injection.
*   Adjust the Shoutcast suffix append logic to ensure compatibility with raw strings after applying the `toRawString()` fix in `ConfigWriter.php`.
*   Deploy the Sigma rule "Detect AzuraCast Liquidsoap Code Injection via API" to detect attempts to exploit this vulnerability through malicious API requests targeting the remote relay password field.
*   Monitor webserver logs for PUT requests to `/api/station/*/remote/*` containing the string `#{#{` in the request body, indicating a potential injection attempt, as shown in the PoC.
