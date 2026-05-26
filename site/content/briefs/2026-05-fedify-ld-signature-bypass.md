---
title: Fedify LD-Signature Bypass via JSON-LD Named-Graph Restructuring
slug: 2026-05-fedify-ld-signature-bypass
description: Fedify is vulnerable to CVE-2026-42462, a Linked Data Signature bypass via JSON-LD Named-Graph Restructuring, allowing attackers to alter third-party signed activities by manipulating the document structure without invalidating the signature, potentially leading to integrity, availability, and confidentiality issues.
date: "2026-05-26T23:40:10Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - fedify
  - ld-signature-bypass
  - json-ld
  - cve-2026-42462
vendors:
  - Fedify
products:
  - '@fedify/fedify (< 2.2.3)'
references:
  - https://github.com/advisories/GHSA-9rfg-v8g9-9367
rules:
  - title: Detect Fedify JSON-LD Restructuring Attack - @graph
    description: Detects CVE-2026-42462 exploitation — Alerts on JSON-LD payloads containing the @graph keyword, indicating a potential restructuring attack attempt against Fedify.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - webserver
  - title: Detect Fedify JSON-LD Restructuring Attack - @included and @reverse
    description: Detects CVE-2026-42462 exploitation — Alerts on JSON-LD payloads containing the @included or @reverse keyword, indicating a potential restructuring attack attempt against Fedify.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - webserver
rules_count: 2
---

Fedify is susceptible to a critical vulnerability that allows attackers to bypass Linked Data Signatures through JSON-LD Named-Graph Restructuring. This issue stems from the ability to manipulate the structure of JSON-LD documents using features like `@graph`, `@included`, and `@reverse` without invalidating the signature. An attacker can move signed activities, alter their content, or even replace them entirely, leading to significant security implications. The vulnerability impacts Fedify versions prior to 2.2.3. Failure to compact JSON-LD documents against an application's local context allows renaming aliases to non-standard names and use non-mapped aliases to replace existing values. This bypass poses a risk to the integrity and confidentiality of data processed by Fedify, as it can be exploited to forge activities. The vulnerability is identified as CVE-2026-42462.

## Attack Chain

1. Attacker crafts a malicious JSON-LD document with a signed Activity.
2. The attacker utilizes JSON-LD features like `@graph` to move the top-level Activity to a `@graph` property and moves the activity's `object` to the top level.
3. Alternatively, the attacker employs the `@reverse` keyword to reverse an Activity and its `object`, changing the document's shape.
4. The attacker can also use the `@included` keyword to move properties outside the normal tree, effectively making them invisible to ActivityPub implementations.
5. The crafted JSON-LD document bypasses signature verification due to the canonical RDF graph representation remaining unchanged.
6. The vulnerable Fedify instance processes the manipulated document without detecting the tampering.
7. If compacting is disabled, the attacker can rename aliases or use non-mapped aliases to replace existing values in the signed JSON-LD document.
8. The attacker successfully alters or forges activities, potentially leading to replay attacks with stripped attributes, content modification, or even complete activity replacement.

## Impact

The exploitation of this vulnerability can lead to significant security breaches. With the `@included` keyword, attackers can replay `Create` and `Update` activities while stripping away critical attributes like content or metadata, leading to integrity and availability issues. The `@graph` and `@reverse` keywords enable changing the root activity, which could allow sending malicious announcements. The lack of compacting against an application's local context allows attackers to rewrite activities arbitrarily. The exploitation can lead to major integrity, availability, and potentially confidentiality issues, such as replacing an actor's inbox. The `@fedify/fedify` package versions less than 2.2.3 are affected.

## Recommendation

*   Upgrade to `@fedify/fedify` version 2.2.3 or later to patch CVE-2026-42462.
*   Implement server-side validation to reject JSON-LD documents containing `@graph`, `@included`, or `@reverse` after compaction, as described in the overview.
*   Ensure JSON-LD documents with verified Linked Data Signatures are compacted against the application's local JSON-LD context to prevent alias manipulation, mitigating the risk described in the overview.
*   Deploy the Sigma rule "Detect Fedify JSON-LD Restructuring Attack" to monitor for exploitation attempts using `@graph`, `@included`, and `@reverse` keywords in JSON-LD payloads.
