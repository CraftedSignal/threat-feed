---
title: Second-Order SSTI in SiYuan via Attribute-View Template Columns
slug: 2026-09-siyuan-ssti
description: SiYuan kernel is vulnerable to a second-order SSTI via the queryBlocks template function, allowing attackers to achieve arbitrary SQL execution upon rendering imported malicious content.
date: "2026-09-04T00:04:41Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:siyuan_note:siyuan:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - ssti
  - sql-injection
  - rce
vendors:
  - SiYuan
products:
  - kernel (< 0.0.0-20260723035036-0a176345e02a)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker-controlled template argument becomes arbitrary SQL... runs the embedded SQL on any kernel that imports and renders it.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: 'Delivered second-order: a shared/imported document or AV package carrying such a column runs the embedded SQL.'
    confidence_band: high
cves:
  - id: CVE-2026-72807
    cvss: 8
    epss: 0.00199
references:
  - https://github.com/advisories/GHSA-x67c-8pwr-m8g3
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72807
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade SiYuan kernel to version 0.0.0-20260723035036-0a176345e02a.
      owner: IT Operations
      due: 48h
      evidence: Upgrade to 0.0.0-20260723035036-0a176345e02a or later.
  mitigation_plan:
    - priority: immediate
      action: Upgrade kernel to 0.0.0-20260723035036-0a176345e02a or later
      owner: IT Operations
      addresses: CVE-2026-72807
      evidence: 'Affected Packages: go/github.com/siyuan-note/siyuan/kernel (vulnerable: < 0.0.0-20260723035036-0a176345e02a)'
---

SiYuan note-taking software is susceptible to a second-order Server-Side Template Injection (SSTI) vulnerability, tracked as CVE-2026-72807. The vulnerability exists within Attribute-View (AV) template columns, which are live-evaluated during rendering. The `queryBlocks` template function, intended for database interaction, fails to use parameterized queries, instead performing raw string substitution into SQL statements. 

While AV creation is restricted to administrators, the injection is delivered as a second-order threat. An attacker can craft a document or an AV package containing a malicious template column. When a victim imports this package and renders the associated Attribute-View, the malicious template executes arbitrary SQL against the application's read-write database handle. This allows for unauthorized data access across notebooks and potential write operations via statement stacking. The vulnerability affects the SiYuan kernel prior to version 0.0.0-20260723035036-0a176345e02a.

## Attack Chain

1. Attacker constructs a SiYuan document or AV package containing a template column using the `queryBlocks` function.
2. The attacker injects malicious SQL commands as an argument to `queryBlocks` (e.g., `.action{range queryBlocks "SELECT * FROM blocks..."}`).
3. The malicious document or AV package is distributed to a victim via file import.
4. The victim imports the document into their local SiYuan instance.
5. The victim triggers the rendering of the Attribute-View (e.g., via `POST /api/av/renderAttributeView`).
6. The SiYuan kernel evaluates the template, substituting the malicious SQL string directly into the database query.
7. The SQLite engine executes the arbitrary SQL commands, potentially exfiltrating data or modifying the database.

## Impact

Successful exploitation leads to unauthorized access to the victim's local SiYuan database. Because the `queryBlocks` function operates on a read-write database handle, an attacker can bypass access controls to read sensitive notes or perform write operations if statement stacking is supported by the SQLite implementation. The severity is bounded by the requirement for victim interaction (importing and rendering content).

## Recommendation

1. Upgrade the SiYuan kernel to version 0.0.0-20260723035036-0a176345e02a or later to resolve CVE-2026-72807.
2. Implement strict input validation and sanitization for all imported document content and AV templates.
3. Replace raw string substitution in the `queryBlocks` function with proper parameterized query bindings.
4. Review and restrict the set of template functions available within Attribute-View columns to prevent access to dangerous primitives.
