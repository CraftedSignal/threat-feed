---
brief_id: brief-2026-10-29-sylphx-pdf-reader-mcp-auth-bypass
event_id: brief-2026-10-29-sylphx-pdf-reader-mcp-auth-bypass
revision: 1
activity_at: "2026-10-29T18:38:00Z"
title: 'sylphx pdf-reader-mcp: HTTP transport authentication bypass (CVE-2026-62264)'
slug: 2026-10-sylphx-pdf-reader-mcp-auth-bypass
description: The @sylphx/pdf-reader-mcp package contains an authentication bypass vulnerability in its HTTP transport implementation that exposes local files and PDF tools to unauthorized network requests.
date: "2026-10-29T18:38:00Z"
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
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:sylphx:pdf-reader-mcp:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - cve-2026-62264
  - mcp
  - nodejs
vendors:
  - sylphx
products:
  - pdf-reader-mcp (< 3.0.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The /mcp endpoint accepted unauthenticated requests, allowing any client able to reach the port to invoke every PDF tool.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Any client able to reach the port could... read the contents of any PDF the server process could open anywhere on the host.
    confidence_band: high
cves:
  - id: CVE-2026-62264
    kev_status: unknown
references:
  - https://github.com/advisories/GHSA-q344-5v34-gm84
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade @sylphx/pdf-reader-mcp to 3.0.1
      owner: IT Operations
      due: 24h
      evidence: Fixed in @sylphx/pdf-reader-mcp@3.0.1.
  hunt_leads:
    - lead: Identify running instances of pdf-reader-mcp and check configuration flags
      technique_id: T1190
      data_needed:
        - Process command line arguments for the node application
        - Application startup logs indicating MCP_HTTP_HOST
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The default bind address of 0.0.0.0 allows any client able to reach the port to invoke tools.
  mitigation_plan:
    - priority: immediate
      action: Bind service to 127.0.0.1 and implement reverse proxy authentication
      owner: IT Operations
      addresses: CVE-2026-62264
      evidence: 'For deployments that cannot upgrade immediately: Bind to loopback only... Place a reverse proxy in front that enforces authentication.'
---

The @sylphx/pdf-reader-mcp package (v2.2.0 through 3.0.0) fails to enforce the `X-API-Key` header when the HTTP transport is enabled. Despite configuring an `MCP_API_KEY`, the application fails to validate the key, resulting in the `/mcp` endpoint accepting unauthenticated requests. Because the default bind address is `0.0.0.0`, any actor with network access to the server can execute PDF parsing tools and access arbitrary files accessible to the application process.

## Impact

Successful exploitation allows unauthorized actors to read any PDF file accessible to the server process and leverage PDF parsing tools. The vulnerability also supports limited Server-Side Request Forgery (SSRF) capabilities. The issue is exacerbated by misleading startup logs that incorrectly confirm authentication as enabled.

## Recommendation

* Upgrade to `@sylphx/pdf-reader-mcp@3.0.1` or later, which enforces API key validation and defaults to loopback-only binding.
* If immediate patching is not possible, restrict network exposure by setting `MCP_HTTP_HOST` to `127.0.0.1`.
* Implement a reverse proxy with authentication enforcement in front of any instances exposed to non-local networks.
* Restrict filesystem access by explicitly defining `MCP_PDF_ALLOWED_DIRS` for the server process.
