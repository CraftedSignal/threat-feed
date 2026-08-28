---
title: Pimcore Unrestricted Deserialization via Object-Store Columns
slug: 2026-08-pimcore-deserialization
description: Pimcore components including Hotspotimage, ImageGallery, Block, and Video perform insecure PHP deserialization on database-stored metadata, enabling remote code execution via object injection.
date: "2026-08-28T21:13:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - php-injection
  - deserialization
  - rce
  - pimcore
vendors:
  - Pimcore
products:
  - Pimcore (<= v2026.1.4, <= v12.3.8)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker who can write the *__hotspots store column with crafted serialized bytes achieves PHP Object Injection (CWE-502).
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-w23p-wrp7-ch38
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - AppSec
  immediate_actions:
    - action: Review DB query logs for update statements targeting *__hotspots columns
      owner: SOC
      due: 24h
      evidence: Source document identifies the column as the storage sink
  mitigation_plan:
    - priority: immediate
      action: Patch Pimcore to the latest version once available; update dependency gadget chains
      owner: IT Operations
      addresses: CWE-502 Deserialization
      evidence: Source identifies unrestricted unserialize() as the root cause
---

Pimcore is vulnerable to PHP Object Injection (CWE-502) due to insecure deserialization practices within its data object model. Specifically, the `getDataFromResource()` method in `Pimcore\Model\DataObject\ClassDefinition\Data\Hotspotimage` and sibling marshallers (`ImageGallery`, `Block`, and `Video`) perform an unrestricted `unserialize()` call on data read from object-store database columns. 

The vulnerability exists because these components use `Pimcore\Tool\Serialize::unserialize()` as a fallback for JSON decoding. The `unserialize()` wrapper defaults to an unrestricted class allowlist, allowing any PHP class present in the application scope to be instantiated. Attackers who can influence the content of the `*__hotspots` object-store columns - for instance, via a separate storage-write or SQL injection primitive - can inject crafted serialized PHP payloads. Upon the next retrieval and loading of the DataObject, the application instantiates these objects and triggers their magic methods (such as `__wakeup` or `__destruct`), enabling Remote Code Execution (RCE) via gadget chains, such as those found in the bundled `guzzlehttp/guzzle` library.

## Attack Chain

1. Attacker gains a write primitive to the Pimcore database, specifically targeting the `*__hotspots` columns in object-store tables.
2. Attacker selects a gadget chain present in the application's dependencies (e.g., `GuzzleHttp\Cookie\FileCookieJar` in `guzzlehttp/guzzle`).
3. Attacker crafts a malicious serialized PHP payload using a tool like `phpggc` to target the chosen gadget.
4. Attacker executes an SQL `UPDATE` statement to overwrite the target object's column with the malicious serialized bytes.
5. The application retrieves the affected DataObject from the database through the standard model loading layer.
6. The `Hotspotimage::getDataFromResource()` method is invoked during object hydration, attempting to JSON decode the payload, which fails.
7. The application falls back to `Serialize::unserialize()`, which deserializes the malicious bytes without an allowlist.
8. Magic methods trigger, executing the gadget chain and achieving the attacker's final objective (e.g., arbitrary file write or RCE).

## Impact

Successful exploitation results in arbitrary code execution on the Pimcore server. This vulnerability affects all currently maintained versions, including `v2026.1.4` and `v12.3.8`. Because these components are heavily used in DataObject management, an attacker with low-level write access to the database can achieve full system compromise.

## Recommendation

1. Immediately audit all custom code and database access layers that interact with object-store columns to prevent unauthorized write access to the metadata columns.
2. Apply upcoming patches from the Pimcore vendor that implement a strictly constrained class allowlist in `Pimcore\Tool\Serialize::unserialize()`.
3. As a temporary mitigation, implement a WAF or database firewall rule to inspect and block serialized PHP strings (e.g., `O:\d+:"`) within SQL queries directed at the application database.
4. Perform periodic integrity checks on `*__hotspots` columns in object-store tables to identify unexpected serialized payloads that deviate from standard JSON formatting.
