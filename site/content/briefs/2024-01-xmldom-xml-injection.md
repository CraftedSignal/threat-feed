---
title: xmldom XML Injection Vulnerability
slug: 2024-01-xmldom-xml-injection
description: The xmldom package is vulnerable to XML injection. The package serializes DocumentType node fields (internalSubset, publicId, systemId) verbatim without any escaping or validation. When these fields are set programmatically to attacker-controlled strings, XMLSerializer.serializeToString can produce output where the DOCTYPE declaration is terminated early and arbitrary markup appears outside it. To address this applications that pass untrusted data to createDocumentType() or write untrusted values directly to a DocumentType node's publicId, systemId, or internalSubset properties should audit all serializeToString() call sites and add the option.
date: "2024-01-03T12:00:00Z"
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

The `@xmldom/xmldom` and `xmldom` packages are vulnerable to XML injection due to the lack of validation when serializing `DocumentType` node fields. Specifically, the `internalSubset`, `publicId`, and `systemId` fields are serialized verbatim without any escaping or validation. This vulnerability affects `@xmldom/xmldom` versions prior to 0.8.13 and versions 0.9.0 to 0.9.9, as well as `xmldom` versions up to 0.6.0. The vulnerability is triggered when these fields are programmatically set to…
