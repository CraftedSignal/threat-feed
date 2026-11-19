---
brief_id: brief-2026-11-19-mssql-mcp-sql-injection-ghsa-2m9m-6cr5-9x25
event_id: brief-2026-11-19-mssql-mcp-sql-injection-ghsa-2m9m-6cr5-9x25
revision: 2
activity_at: "2026-11-19T18:10:37Z"
revision_history:
  - revision: 2
    at: "2026-11-19T18:10:37Z"
    checksum: sha256:9b7ec9e051d2159fa61dc1735f90e9a69c28cf50dcc17deaf5e01d21a635c2dc
    summary: poc_available
    changed_fields:
      - cve_verification
      - cves
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=58A22638-9E61-5ADC-9DC8-6E2F22290C2B&utm_source=rss&utm_medium=rss
title: ConnorBritain mssql-mcp-core SQL injection (CVE-2026-63129)
slug: 2026-11-mssql-mcp-sql-injection-ghsa-2m9m-6cr5-9x25
description: The mssql-mcp-core library and related packages are vulnerable to SQL injection through unparameterized identifier and WHERE clause interpolation, allowing malicious actors to bypass safeguards and execute stacked T-SQL commands.
date: "2026-11-19T04:09:22Z"
lastmod: "2026-11-19T18:07:01Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=58A22638-9E61-5ADC-9DC8-6E2F22290C2B&utm_source=rss&utm_medium=rss
vendors:
  - ConnorBritain
products:
  - mssql-mcp-core
  - mssql-mcp-reader
  - mssql-mcp-server
  - mssql-mcp-writer
product_versions:
  - product: mssql-mcp-core
    range: <= 0.5.0
  - product: mssql-mcp-reader
    range: <= 0.4.2
  - product: mssql-mcp-server
    range: <= 0.5.2
  - product: mssql-mcp-writer
    range: <= 0.4.2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An actor who can supply tool arguments (a malicious or compromised MCP client, or an LLM agent steered via indirect prompt injection) could read, modify, or drop arbitrary data.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: a crafted input enabled stacked statements (arbitrary DDL/DML), sub-selects, and (with a privileged login and xp_cmdshell enabled) OS command execution.
    confidence_band: high
cve_verification:
  CVE-2026-63129:
    status: verified
    source: nvd
    checked_at: 2026-11-19T18:07:01.645406871Z
cves:
  - id: CVE-2026-63129
    cvss: 8.8
    epss: 0.00553
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-2m9m-6cr5-9x25
  - https://cveawg.mitre.org/api/cve/CVE-2026-63129
  - https://sploitus.com/exploit?id=58A22638-9E61-5ADC-9DC8-6E2F22290C2B&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  hunt_leads:
    - lead: Identify SQL Server logs containing stacked query patterns, such as sequences of statements separated by semicolons within a single request, specifically originating from the service account used by mssql-mcp.
      technique_id: T1059.003
      data_needed:
        - SQL Server Audit Logs
        - Database transaction logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Request.query() submits a multi-statement T-SQL batch, so a crafted input enabled stacked statements (arbitrary DDL/DML), sub-selects
updates:
  - at: "2026-11-19T18:07:01Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=58A22638-9E61-5ADC-9DC8-6E2F22290C2B&utm_source=rss&utm_medium=rss
---

## Overview

mssql-mcp-core is the foundational library for several Model Context Protocol (MCP) tools that facilitate interactions with Microsoft SQL Server. A vulnerability exists in how these tools construct T-SQL queries by interpolating caller-supplied identifiers (such as table names and columns) and predicate strings directly into database batches via the node-mssql `Request.query()` API. This behavior ignores parameterization for all but data values, permitting an attacker to escape intended query structures. The flaw affects the reader, writer, and server packages that rely on the core library. This issue is documented under CVE-2026-63129.

## Impact

An actor who can supply input to MCP tools can bypass row-count limits, preview requirements, and confirmation controls. By injecting stacked T-SQL statements, an attacker can read, modify, or delete arbitrary database content. Furthermore, if the underlying SQL Server login possesses high privileges and `xp_cmdshell` is enabled, the attacker may be able to achieve arbitrary operating-system command execution.

## Recommendation

Upgrade all consumer packages to their fixed versions immediately:
- Update `@connorbritain/mssql-mcp-core` to 0.6.0.
- Update `@connorbritain/mssql-mcp-server` to 0.6.0.
- Update `@connorbritain/mssql-mcp-reader` to 0.5.0.
- Update `@connorbritain/mssql-mcp-writer` to 0.5.0.

As a defense-in-depth measure, ensure the database server operates under a least-privilege SQL login and explicitly disable `xp_cmdshell` if not required for business operations. Restrict which MCP clients have permission to invoke tools that interact with the database.
