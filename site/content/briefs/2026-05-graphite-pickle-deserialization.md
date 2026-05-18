---
title: Graphite graph database engine Insecure Deserialization Vulnerability
slug: 2026-05-graphite-pickle-deserialization
description: Graphite versions before 0.2 are vulnerable to insecure deserialization due to the use of Python's `pickle` module for database storage, allowing attackers to craft malicious database files that execute arbitrary code when loaded.
date: "2026-05-18T13:29:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - insecure-deserialization
  - code-execution
  - graphitedb
vendors:
  - Graphite
products:
  - graphitedb (< 0.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
references:
  - https://github.com/advisories/GHSA-qw48-84f6-28gv
  - https://github.com/mkh-user/graphite/releases
  - https://docs.python.org/3/library/pickle.html#module-pickle
rules:
  - title: Detect Attempt to Load Pickle File in Patched Graphite
    description: Detects attempts to load pickle files in Graphite versions 0.2 and later, which should not occur under normal circumstances.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

Graphite, a graph database engine, is susceptible to insecure deserialization in versions prior to 0.2. This vulnerability arises from the use of Python's `pickle` module for serializing and deserializing database files. The `pickle` module is known to be unsafe when handling data from untrusted sources because it allows arbitrary code execution during the deserialization process. An attacker can exploit this by crafting a malicious Graphite database file containing embedded commands. When a vulnerable Graphite instance loads this file, the embedded commands are executed, leading to potential system compromise. The vulnerability has been patched in version 0.2, which migrates to a safer JSON-based storage format.

## Attack Chain

1.  Attacker crafts a malicious Graphite database file. This file contains serialized Python objects with malicious code embedded within them, leveraging the `pickle` module's capability to execute arbitrary code during deserialization.
2.  The attacker delivers the malicious database file to the target. This could be achieved through various means, such as social engineering, compromised file shares, or as part of a larger attack chain.
3.  The victim, running a vulnerable version of Graphite (prior to 0.2), attempts to load the database file. This action triggers the `pickle.load()` function.
4.  During the deserialization process, the `pickle` module executes the malicious code embedded in the serialized Python objects.
5.  The attacker gains arbitrary code execution within the context of the Graphite process. This allows the attacker to perform various malicious activities, such as installing backdoors, stealing sensitive data, or disrupting services.
6.  The attacker establishes persistence on the system, ensuring continued access even after the initial compromise.
7.  The attacker escalates privileges to gain administrative control over the system.
8.  The attacker uses the compromised system to move laterally within the network, compromising other systems and expanding their foothold.

## Impact

Successful exploitation of this vulnerability allows attackers to achieve arbitrary code execution on systems running vulnerable versions of Graphite. The primary consequence is complete system compromise, including the potential for data theft, service disruption, and further lateral movement within the network. This vulnerability affects users who load database files from untrusted sources. Users of Graphite graph database engine versions before 0.2 are potentially impacted.

## Recommendation

-   Upgrade to Graphite version 0.2 or later to mitigate the `pickle` deserialization vulnerability, as it utilizes JSON for database storage instead (`graphite.Migration` module documentation).
-   Refrain from loading Graphite database files from untrusted or unknown sources when using versions prior to 0.2 (see Workarounds).
-   Migrate existing pickle-based Graphite databases to the JSON format using the provided `convert_pickle_to_json` function from the `graphite.Migration` module (see Workarounds).
-   Deploy the following Sigma rule to detect attempts to load pickle files when running a patched version of Graphite.
