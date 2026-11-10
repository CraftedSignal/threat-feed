---
brief_id: brief-2026-11-10-pgedge-mcp-dns-rebinding
event_id: brief-2026-11-10-pgedge-mcp-dns-rebinding
revision: 1
activity_at: "2026-11-10T18:59:54Z"
title: 'pgEdge Postgres MCP Server: DNS rebinding via Origin header validation flaw (CVE-2026-125320)'
slug: 2026-11-pgedge-mcp-dns-rebinding
description: The pgEdge Postgres MCP Server prior to version 1.1.0 fails to validate the Origin header, enabling DNS rebinding attacks that allow an attacker-controlled web page to exfiltrate database schemas and query results.
date: "2026-11-10T18:59:54Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Patch released and available; environment validation required to identify active HTTP transport instances.
cpes:
  - cpe:2.3:a:pgedge:postgres_mcp_server:*:*:*:*:*:*:*:*
vendors:
  - pgEdge
products:
  - pgEdge Postgres MCP Server (< 1.1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: A user who visited an attacker-controlled page could be targeted through DNS rebinding.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: allowing the page to reach a locally running server and read schemas and query results from configured databases.
    confidence_band: high
cves:
  - id: CVE-2026-125320
    cvss: 5.3
    kev_status: "false"
references:
  - https://github.com/pgEdge/pgedge-postgres-mcp/security/advisories/GHSA-6hg5-9f3w-c886
  - https://github.com/pgEdge/pgedge-postgres-mcp/releases/tag/v1.1.0
  - https://sploitus.com/exploit?id=CVE-2026-125320
  - https://sploitus.com/exploit?id=CVE-2026-125320&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade pgEdge Postgres MCP Server to version 1.1.0 or later
      owner: IT Operations
      due: 48h
      evidence: This issue is fixed in version 1.1.0.
  hunt_leads:
    - lead: Identify endpoints running pgEdge Postgres MCP Server with HTTP transport enabled
      data_needed:
        - Process list with command line arguments (e.g., --http-port)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The issue affected deployments with the HTTP transport enabled on a machine that also ran a browser.
  mitigation_plan:
    - priority: immediate
      action: Disable HTTP transport for pgEdge Postgres MCP Server
      owner: IT Operations
      addresses: CVE-2026-125320
      evidence: the default stdio transport was not reachable through this path.
---

The pgEdge Postgres MCP Server (prior to version 1.1.0) contains a vulnerability in its HTTP transport mechanism where the Origin header is not validated. An attacker can leverage this via DNS rebinding when a user visits a malicious website while the pgEdge service is running locally on the same machine. This enables the attacker to interact with the server and read database schemas or query results from connected PostgreSQL databases. The default stdio transport method is not affected.

## Impact
Successful exploitation allows unauthorized access to sensitive database schemas and query results. The impact is limited to the data accessible to the pgEdge Postgres MCP Server instance.

## Recommendation
- Upgrade the pgEdge Postgres MCP Server to version 1.1.0 or later immediately to apply the Origin header validation fix.
- Audit environments for workstations running the pgEdge Postgres MCP Server with HTTP transport enabled.
- If immediate patching is not possible, disable the HTTP transport and utilize the stdio transport exclusively.
