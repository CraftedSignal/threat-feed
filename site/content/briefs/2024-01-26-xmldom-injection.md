---
title: xmldom XML Node Injection via Comment Serialization
slug: 2024-01-26-xmldom-injection
description: The xmldom library is vulnerable to XML node injection, allowing attackers to inject arbitrary XML nodes into serialized output by manipulating comment content; this is mitigated by using the `requireWellFormed` option in `serializeToString` after upgrading to version 0.8.13 or 0.9.10.
date: "2024-01-26T12:00:00Z"
type: advisory
types:
  - advisory
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

The xmldom library is susceptible to XML node injection due to a lack of validation when serializing comment nodes. Versions prior to 0.8.13 and versions between 0.9.0 and 0.9.10 are vulnerable. An attacker can inject arbitrary XML nodes into the serialized output by including comment-breaking sequences (e.g., `-->`) in the comment data. This allows them to alter the structure of the XML document. Exploitation involves crafting malicious input that leverages the library's DOM construction and serialization flow. It matters because applications using xmldom to process potentially untrusted XML data could be coerced into generating malicious XML structures. The fix requires an opt-in `requireWellFormed` flag to be enabled when calling `serializeToString()`.

## Attack Chain

1. An application receives untrusted data intended for use in XML comment content.
2. The application calls `createComment(data)` in xmldom, passing the untrusted data. The library stores the data without proper validation.
3. The application constructs an XML document, including the comment node created in the previous step.
4. The application calls `serializeToString()` on the XML document to serialize it.
5. If the untrusted data contains comment-breaking sequences, such as `-->`, the serializer prematurely terminates the comment.
6. The serializer injects any subsequent content in the untrusted data as live XML markup.
7. The application stores, forwards, signs, or hands the serialized XML to another parser.
8. The downstream consumer trusts the altered XML structure, leading to unintended consequences, such as misconfiguration or security bypass.

## Impact

Successful exploitation allows attackers to inject arbitrary XML nodes, potentially altering the structure and meaning of generated XML documents. This could lead to misconfiguration, policy bypass, or other security vulnerabilities in applications that rely on the integrity of the XML structure. The vulnerability affects applications that use xmldom to build XML from untrusted input. The number of victims depends on the usage of the vulnerable library and the exposure of applications to untrusted XML data.

## Recommendation

*   Upgrade to `@xmldom/xmldom` version 0.8.13 or 0.9.10 or later to gain access to the fix.
*   Audit all calls to `serializeToString()` and add the `{ requireWellFormed: true }` option when serializing comments containing potentially untrusted data.
*   Implement server-side input validation to sanitize comment data by removing comment-breaking sequences like `-->` before passing it to `createComment()`.
*   Deploy the Sigma rule to detect comment injections.
