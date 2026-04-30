---
title: xmldom XML Injection Vulnerability
slug: 2024-01-xmldom-xml-injection
description: The xmldom package is vulnerable to XML injection. The package serializes DocumentType node fields (internalSubset, publicId, systemId) verbatim without any escaping or validation. When these fields are set programmatically to attacker-controlled strings, XMLSerializer.serializeToString can produce output where the DOCTYPE declaration is terminated early and arbitrary markup appears outside it. To address this applications that pass untrusted data to createDocumentType() or write untrusted values directly to a DocumentType node's publicId, systemId, or internalSubset properties should audit all serializeToString() call sites and add the option.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xml-injection
  - xxe
  - dom
  - xmldom
vendors:
  - npm
products:
  - '@xmldom/xmldom'
  - xmldom
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://github.com/advisories/GHSA-f6ww-3ggp-fr8h
rules:
  - title: Detect XMLSerializer Usage Without requireWellFormed
    description: Detects calls to XMLSerializer.serializeToString without the requireWellFormed option, which might indicate a potential vulnerability if user-controlled data influences DocumentType node fields.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - process_creation
      - linux
  - title: Detect createDocumentType calls with user-controlled input
    description: Detects calls to createDocumentType with arguments derived from user-controlled input, indicating a potential vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The `@xmldom/xmldom` and `xmldom` packages are vulnerable to XML injection due to the lack of validation when serializing `DocumentType` node fields. Specifically, the `internalSubset`, `publicId`, and `systemId` fields are serialized verbatim without any escaping or validation. This vulnerability affects `@xmldom/xmldom` versions prior to 0.8.13 and versions 0.9.0 to 0.9.9, as well as `xmldom` versions up to 0.6.0. The vulnerability is triggered when these fields are programmatically set to attacker-controlled strings, leading to potential arbitrary markup injection outside the DOCTYPE declaration during serialization using `XMLSerializer.serializeToString`. This can lead to downstream XML parsers being susceptible to XXE attacks. Defenders should audit serializeToString() call sites and add `{ requireWellFormed: true }` to mitigate this vulnerability.

## Attack Chain

1.  The attacker identifies an application using a vulnerable version of `@xmldom/xmldom` or `xmldom`.
2.  The attacker finds a code path where they can control the `publicId`, `systemId`, or `internalSubset` properties of a `DocumentType` node.
3.  The attacker crafts a malicious string containing XML injection payloads (e.g., closing DOCTYPE tags or injecting SYSTEM entities).
4.  The attacker uses programmatic calls to `createDocumentType` or direct property writes to set the malicious string as the value of the `publicId`, `systemId`, or `internalSubset` field.
5.  The application calls `XMLSerializer.serializeToString` on the document, without the `{ requireWellFormed: true }` option.
6.  The vulnerable serializer emits a DOCTYPE declaration where the injected malicious string is included verbatim, causing the DOCTYPE declaration to be terminated early or to include injected entities.
7.  The serialized XML is passed to a downstream XML parser that performs entity expansion.
8.  The downstream XML parser expands the injected entities, leading to potential XXE attacks, information disclosure, or other malicious actions.

## Impact

Successful exploitation of this vulnerability can lead to the injection of arbitrary XML markup, potentially enabling XXE attacks against downstream XML parsers. The impact includes potential information disclosure, arbitrary code execution, or denial-of-service if the downstream parser expands external entities. This vulnerability impacts applications using vulnerable versions of `@xmldom/xmldom` and `xmldom` that construct `DocumentType` nodes from user-controlled data and serialize the document without proper validation.

## Recommendation

*   Upgrade to `@xmldom/xmldom` version 0.8.13 or later, or version 0.9.10 or later, to receive the fix.
*   Upgrade to a version of `xmldom` greater than 0.6.0.
*   Audit all calls to `XMLSerializer.serializeToString()` and add the option `{ requireWellFormed: true }` to enforce validation of `DocumentType` node fields, as described in the advisory.
*   Applications that pass untrusted data to `createDocumentType()` or write untrusted values directly to a `DocumentType` node's `publicId`, `systemId`, or `internalSubset` properties should audit all `serializeToString()` call sites and add the option.
