---
title: ArcadeDB Trigger Script RCE via Java.lang.* Allow-list
slug: 2026-07-arcadedb-rce
description: A vulnerability in ArcadeDB's ScriptTriggerExecutor allows users with UPDATE_SCHEMA privileges to achieve OS Remote Code Execution (RCE) due to a permissive allow-list for trigger scripts, enabling direct calls to `java.lang.Runtime.exec()` when a malicious trigger script is created and fired.
date: "2026-07-16T20:17:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ArcadeDB
  - RCE
  - vulnerability
  - java
  - database
  - privilege-escalation
vendors:
  - ArcadeDB
products:
  - arcadedb-engine (< 26.7.2)
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: a trigger script do Java.type("java.lang.Runtime").getRuntime().exec(...)
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: obtains OS RCE when the trigger fires...escalating privileges from a schema administrator to the underlying OS
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-x9f9-r4m8-9xc2
---

A high-severity vulnerability has been identified in ArcadeDB, affecting versions prior to 26.7.2. The `ScriptTriggerExecutor` component, responsible for executing trigger scripts, includes `java.lang.*` in its allowed packages. This oversight permits an authenticated attacker with `UPDATE_SCHEMA` privileges (a schema administrator) to craft and deploy a malicious JavaScript trigger. When such a trigger fires, it can invoke `java.lang.Runtime.exec()`, leading to arbitrary operating system command execution on the host server where ArcadeDB is running. This effectively escalates privileges from a database schema administrator to remote code execution on the underlying operating system, posing a significant risk to the integrity and confidentiality of the host system and the data stored within ArcadeDB.

## Attack Chain

1. An attacker gains `UPDATE_SCHEMA` administrative privileges within an ArcadeDB instance.
2. The attacker crafts a malicious database trigger script that includes an OS command execution payload.
3. The attacker registers this malicious trigger within ArcadeDB using the `CREATE TRIGGER ... EXECUTE JAVASCRIPT` command.
4. The JavaScript payload within the trigger leverages the permissive `java.lang.*` allow-list to call `Java.type("java.lang.Runtime").getRuntime().exec(...)`.
5. The crafted trigger is saved into the database schema, awaiting its activation conditions.
6. A subsequent database operation or event occurs that satisfies the conditions for the newly created malicious trigger to fire.
7. The ArcadeDB `ScriptTriggerExecutor` processes the trigger, and due to `java.lang.*` being in the allow-list, the `java.lang.Runtime.exec()` call is permitted.
8. The attacker's specified operating system commands are executed on the host server with the privileges of the ArcadeDB process, achieving remote code execution.

## Impact

Successful exploitation of this vulnerability results in arbitrary remote code execution on the server hosting ArcadeDB. This allows an attacker to completely compromise the underlying operating system, potentially leading to data exfiltration, deletion, or modification of any data accessible by the ArcadeDB process. While it requires an attacker to first obtain `UPDATE_SCHEMA` privileges, the RCE then allows for privilege escalation from a schema administrator role to full system control. The compromise can affect any operating system ArcadeDB is deployed on, including Windows, Linux, and macOS.

## Recommendation

* Upgrade ArcadeDB installations immediately to version 26.7.2 or later to apply the official patch.
* Review and ensure strict access controls are in place for users assigned `UPDATE_SCHEMA` privileges.
* Administrators should monitor database logs for suspicious `CREATE TRIGGER` statements that include `JAVASCRIPT` execution.
