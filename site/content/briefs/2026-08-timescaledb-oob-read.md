---
title: Out-of-Bounds Read in TimescaleDB Dictionary Compression
slug: 2026-08-timescaledb-oob-read
description: An out-of-bounds read vulnerability in the TimescaleDB Dictionary compression reverse row iterator allows authenticated attackers with DML access to disclose sensitive backend memory and shared buffer pool contents.
date: "2026-08-06T23:31:41Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Timescale
products:
  - TimescaleDB (2.29.1)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: An attacker with DML access to a compressed table can craft a malicious datum that causes the reverse iterator to read out-of-bounds memory.
    confidence_band: high
cves:
  - id: CVE-2026-70634
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-70634
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Database Administration
  immediate_actions:
    - action: Upgrade TimescaleDB to version containing commit 517c13e
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-70634 patch reference
  mitigation_plan:
    - priority: immediate
      action: Review and audit DML permissions on compressed database relations
      owner: Database Administration
      addresses: CVE-2026-70634
      evidence: Source states vulnerability requires DML access
---

TimescaleDB versions up to and including 2.29.1 contain an out-of-bounds read vulnerability (CVE-2026-70634) located within the Dictionary compression reverse row iterator (tsl/src/compression/algorithms/dictionary.c). While the forward decoding path correctly validates index values, the reverse path relies on an assertion that is omitted in production release builds. This oversight leaves the 64-bit Simple8b index unvalidated and the read offset effectively attacker-controlled. 

An attacker possessing DML (Data Manipulation Language) access to a physical compressed relation can insert a specifically crafted datum. By subsequently executing a reverse-order scan on the table, the attacker can trigger the out-of-bounds read. If the targeted column utilizes a pass-by-value type, the database engine returns the out-of-bounds memory contents to the client as a legitimate column value. This mechanism bypasses standard SQL access controls, potentially leaking sensitive information stored within the backend memory and the shared buffer pool. The vulnerability is patched in commit 517c13e.

## Impact

Successful exploitation allows for the unauthorized disclosure of sensitive server-side memory, including contents of the shared buffer pool. This information leakage could expose credentials, data from other user sessions, or other proprietary information resident in the database backend memory. The vulnerability is restricted to authenticated users with DML privileges on compressed tables, limiting the attack surface to existing database users.

## Recommendation

1. Upgrade all TimescaleDB instances to a version containing the fix (commit 517c13e or later).
2. Review database user permissions and restrict DML access to sensitive compressed relations to trusted accounts only.
3. Monitor database logs for unusual reverse-order scan queries or suspicious DML activity on compressed tables if database auditing is available.
