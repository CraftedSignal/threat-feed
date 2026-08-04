---
title: Remote Code Execution in ArcadeDB via Script Triggers
slug: 2026-08-arcadedb-rce
description: An authenticated remote code execution vulnerability (CVE-2026-67340) in ArcadeDB engine versions before 26.7.2 allows attackers to escape script sandboxing and execute arbitrary OS commands.
date: "2026-08-01T13:51:11Z"
lastmod: "2026-08-04T13:42:45Z"
type: advisory
types:
  - advisory
severities:
  - critical
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=8EADDC1D-DA94-52A3-8A10-B50387490F94&utm_source=rss&utm_medium=rss
tags:
  - cve-2026-67340
  - rce
  - database
  - arcadedb
vendors:
  - ArcadeData
products:
  - arcadedb-engine
  - ArcadeDB (< 26.7.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An authenticated user with UPDATE_SCHEMA permission can create a JavaScript trigger that invokes java.lang.Runtime.getRuntime().exec() (or ProcessBuilder), achieving OS command execution when the trigger fires.
    confidence_band: high
cves:
  - id: CVE-2026-67340
    cvss: 9.8
    epss: 0.00523
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67340
  - https://github.com/ArcadeData/arcadedb/security/advisories/GHSA-x9f9-r4m8-9xc2
  - https://www.vulncheck.com/advisories/arcadedb-before-remote-code-execution-via-trigger-scripts
  - https://sploitus.com/exploit?id=8EADDC1D-DA94-52A3-8A10-B50387490F94&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=8EADDC1D-DA94-52A3-8A10-B50387490F94
ioc_counts:
  url: 1
updates:
  - at: "2026-08-04T13:42:45Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=8EADDC1D-DA94-52A3-8A10-B50387490F94&utm_source=rss&utm_medium=rss
---

ArcadeDB versions prior to 26.7.2 are vulnerable to remote code execution due to a flaw in the `ScriptTriggerExecutor` component. The vulnerability arises because the engine permits trigger scripts to access host classes within the `java.lang.*` package via the `Java.type` object. Because these packages are explicitly added to the allowed list, an authenticated user possessing the `UPDATE_SCHEMA` permission can register a malicious JavaScript trigger. This trigger can instantiate and invoke sensitive Java classes such as `java.lang.Runtime.getRuntime().exec()` or `ProcessBuilder` to execute arbitrary commands at the operating system level. This issue poses a critical risk to organizations utilizing ArcadeDB, as it allows for full compromise of the underlying server infrastructure by any user with standard schema-management privileges.

## Attack Chain

1. Attacker authenticates to the ArcadeDB instance using valid, low-privileged credentials that include the `UPDATE_SCHEMA` permission.
2. Attacker interacts with the database schema management interface to initiate the creation of a new database trigger.
3. Attacker crafts a payload using JavaScript that leverages the insecure `Java.type` object to gain access to the restricted `java.lang.Runtime` class.
4. Attacker defines the trigger script, embedding the Java runtime command execution logic within the trigger definition.
5. The ArcadeDB server registers the malicious JavaScript code within the `ScriptTriggerExecutor` engine.
6. The trigger event occurs (e.g., an insert, update, or delete operation on the target collection), causing the `ScriptTriggerExecutor` to evaluate the script.
7. The Java Virtual Machine executes the malicious OS commands with the privileges of the ArcadeDB process.
8. Final objective achieved: full code execution and potential persistence or system exfiltration.

## Impact

Successful exploitation of CVE-2026-67340 leads to complete remote code execution on the server hosting the ArcadeDB instance. Given the critical severity (CVSS 9.8), an attacker gaining this level of access can exfiltrate sensitive database contents, modify records, or pivot into the internal network. The scope of impact is limited to environments where attackers have obtained authenticated access to the database with schema modification capabilities.

## Recommendation

* Upgrade the `arcadedb-engine` component to version 26.7.2 or later immediately to address the insecure sandboxing configuration.
* Audit all existing database triggers for unauthorized scripts or suspicious use of `Java.type` references.
* Restrict the `UPDATE_SCHEMA` permission to the smallest number of administrative accounts necessary to limit the potential attack surface.
* Monitor database administrative logs for unexpected calls to trigger creation or modification commands originating from non-administrative service accounts.
