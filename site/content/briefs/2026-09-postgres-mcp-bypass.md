---
title: Postgres MCP Pro Restricted Mode Bypass (CVE-2026-85620)
slug: 2026-09-postgres-mcp-bypass
description: Postgres MCP Pro version 0.3.0 is vulnerable to a restricted-mode bypass due to improper function-name validation within RangeFunction nodes in FROM clauses, enabling arbitrary file read.
date: "2026-09-04T15:28:04Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:postgres:mcp_pro:*:*:*:*:*:*:*:*
vendors:
  - Postgres
products:
  - Postgres MCP Pro (0.3.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Postgres MCP Pro 0.3.0 contains a restricted-mode bypass vulnerability where function-name validation is not applied to RangeFunction nodes in FROM clauses.
    confidence_band: high
cves:
  - id: CVE-2026-85620
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85620
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  mitigation_plan:
    - priority: immediate
      action: Monitor database query logs for patterns matching FROM-clause execution of file-read functions.
      owner: SOC
      addresses: CVE-2026-85620
      evidence: Source document describes file-read bypass via FROM-clause syntax.
---

Postgres MCP Pro version 0.3.0 contains a vulnerability (CVE-2026-85620) that allows for a restricted-mode bypass. The flaw resides in the handling of RangeFunction nodes within SQL FROM clauses. Specifically, the application fails to apply necessary function-name validation logic to these nodes, allowing an attacker to invoke sensitive functions that are intended to be restricted. By crafting specific SQL queries that utilize these functions within a FROM clause, an attacker can bypass defined security constraints to execute functions such as pg_read_file. This results in unauthorized access to arbitrary files residing on the host system. This vulnerability is significant for defenders as it allows for information disclosure, potentially leading to the extraction of sensitive credentials, configuration files, or system data, depending on the permissions of the Postgres service account.

## Impact

Successful exploitation of CVE-2026-85620 grants an attacker the ability to read arbitrary files from the filesystem of the server hosting the Postgres MCP Pro service. This compromise can lead to the exfiltration of sensitive information, including configuration files, local keys, and system metadata, which may be leveraged for further privilege escalation or lateral movement within the network.

## Recommendation

Prioritized, concrete actions for detection engineering teams:
- Audit database logs for SQL queries containing both 'FROM' and 'pg_read_file' or other file-access functions within the same statement.
- Implement monitoring for unauthorized attempts to access sensitive file paths (e.g., /etc/passwd, .ssh/id_rsa) via database-linked functions.
- Upgrade Postgres MCP Pro to a version that addresses CVE-2026-85620 as soon as the vendor releases a patch.
- Restrict the permissions of the database service account to the absolute minimum necessary for business operations to limit the impact of potential file-read exploitation.
