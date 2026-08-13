---
title: 'CVE-2026-73514: Out-of-Bounds Write in PostGIS address_standardizer'
slug: 2026-08-postgis-oob-write
description: The PostGIS address_standardizer extension through version 3.7.0 is vulnerable to an out-of-bounds write allowing database users to trigger memory corruption and potential code execution.
date: "2026-08-13T16:56:52Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - PostGIS
products:
  - address_standardizer (<= 3.7.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A database user with the ability to supply caller-controlled relation names to standardize_address() to trigger memory corruption by providing a rules table with a classification Type value exceeding the fixed class range.
    confidence_band: high
cves:
  - id: CVE-2026-73514
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73514
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Patch PostGIS address_standardizer to version post-3.7.0
      owner: IT Operations
      due: 7d
      evidence: CVE-2026-73514 remediation
  mitigation_plan:
    - priority: immediate
      action: Revoke table creation/modification rights for untrusted database users
      owner: Database Administration
      addresses: CVE-2026-73514
      evidence: The attack requires supply of a caller-controlled relation name.
---

The address_standardizer extension for PostGIS, commonly used for parsing and standardizing address data, contains an out-of-bounds write vulnerability identified as CVE-2026-73514. The vulnerability exists in all versions up to and including 3.7.0 and is addressed in commit 423570b. The issue arises when the `standardize_address()` function processes a caller-supplied rules table. 

An attacker with authenticated access to the database - specifically one who can create or modify tables used as rules by the extension - can supply a 'Type' value that exceeds the intended fixed range. The extension fails to perform bounds checking on this value before using it as an index into an internal output-link table. This results in an out-of-bounds memory write, which can be leveraged to corrupt memory, cause a denial-of-service (crash), or potentially achieve arbitrary code execution within the database process context. This vulnerability is particularly relevant to environments where low-privileged users are granted the ability to create database objects or manipulate data used by administrative extensions.

## Impact

Successful exploitation of this vulnerability allows an authenticated attacker to compromise the integrity of the database process memory. This can lead to service instability, database crashes, or potential escalation of privileges via code execution. The scope of impact is limited to database users with sufficient permissions to manipulate tables passed to the `standardize_address()` function.

## Recommendation

1. Upgrade the PostGIS address_standardizer extension to a version containing the fix implemented in commit 423570b.
2. Audit database permissions to identify users with the ability to create or modify tables that are utilized as input for the `standardize_address()` function.
3. Implement strict access controls on the PostGIS extension functions to ensure only trusted users can invoke `standardize_address()` with custom-defined rules tables.
4. Monitor database logs for repeated errors or unexpected restarts of the PostgreSQL service, which may indicate crash attempts associated with exploitation of this vulnerability.
