---
title: Arbitrary Local File Read Vulnerability in firecrawl-mcp-server
slug: 2026-09-firecrawl-mcp-server-lfr
description: The firecrawl-mcp-server version 3.20.2 is vulnerable to arbitrary local file read attacks because the firecrawl_parse tool fails to validate directory containment for the filePath argument.
date: "2026-09-04T15:27:34Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:firecrawl:firecrawl-mcp-server:3.20.2:*:*:*:*:*:*:*
vendors:
  - Firecrawl
products:
  - firecrawl-mcp-server (3.20.2)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Attackers can supply absolute paths or directory traversal sequences to read sensitive files like credentials and environment variables.
    confidence_band: high
cves:
  - id: CVE-2026-85606
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85606
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Inventory all instances of firecrawl-mcp-server 3.20.2 in the environment.
      owner: IT Operations
      due: 24h
      evidence: Source confirms version 3.20.2 is affected by CVE-2026-85606.
  mitigation_plan:
    - priority: immediate
      action: Upgrade or restrict access to the firecrawl-mcp-server instance.
      owner: IT Operations
      addresses: CVE-2026-85606
      evidence: NVD vulnerability disclosure regarding unconstrained filePath arguments.
---

The firecrawl-mcp-server application, specifically version 3.20.2, contains a critical security flaw in the firecrawl_parse tool. This tool accepts user-provided filePath arguments without performing adequate directory containment validation. An attacker can exploit this lack of sanitization by providing absolute file paths or directory traversal sequences (e.g., ../../../etc/passwd). 

When processed by the MCP server, the application reads the specified file and returns its content to the calling model context. This allows unauthorized actors to exfiltrate sensitive local files, including configuration files, environment variables containing API keys, and system credentials, from the host environment where the MCP server is deployed. Because these servers are often integrated into AI orchestration workflows, successful exploitation directly exposes the underlying environment's secrets to the language model and its users.

## Impact

Successful exploitation of this vulnerability leads to the unauthorized disclosure of sensitive system files and credentials. This could result in the compromise of secondary services if environment variables or private keys are exposed, potentially leading to privilege escalation, lateral movement, or complete host takeover depending on the privileges granted to the user running the MCP server process.

## Recommendation

Prioritized actions for security and platform engineering teams:
* Audit all deployments of firecrawl-mcp-server for version 3.20.2 and update to a patched version once available.
* Implement strict filesystem sandboxing for the MCP server instance, such as running the application in a restricted container with a read-only root filesystem and restricted access to sensitive paths.
* Restrict network access to the MCP server to authorized users or service accounts only.
* Monitor application logs for anomalous file read requests or unexpected patterns in filePath parameters.
