---
title: xmldom XML Node Injection via Comment Serialization
slug: 2024-01-26-xmldom-injection
description: The xmldom library is vulnerable to XML node injection, allowing attackers to inject arbitrary XML nodes into serialized output by manipulating comment content; this is mitigated by using the `requireWellFormed` option in `serializeToString` after upgrading to version 0.8.13 or 0.9.10.
date: "2024-01-26T12:00:00Z"
severities:
  - high
tags:
  - xml
  - injection
  - deserialization
  - vulnerability
vendors:
  - xmldom
products:
  - xmldom
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Controls
references:
  - https://github.com/advisories/GHSA-j759-j44w-7fr8
rules:
  - title: Detect XML Node Injection via xmldom Comment Serialization
    description: Detects XML node injection attempts by identifying comment nodes containing comment breaking sequences.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - process_creation
      - linux
  - title: Detect serializeToString() calls without requireWellFormed
    description: Detects potentially vulnerable calls to serializeToString() without the requireWellFormed option.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The xmldom library is susceptible to XML node injection due to a lack of validation when serializing comment nodes. Versions prior to 0.8.13 and versions between 0.9.0 and 0.9.10 are vulnerable. An attacker can inject arbitrary XML nodes into the serialized output by including comment-breaking sequences (e.g., `-->`) in the comment data. This allows them to alter the structure of the XML document. Exploitation involves crafting malicious input that leverages the library's DOM construction and…
