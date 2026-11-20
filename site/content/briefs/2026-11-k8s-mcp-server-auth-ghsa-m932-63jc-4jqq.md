---
brief_id: brief-2026-11-20-k8s-mcp-server-auth-ghsa-m932-63jc-4jqq
event_id: brief-2026-11-20-k8s-mcp-server-auth-ghsa-m932-63jc-4jqq
revision: 1
activity_at: "2026-11-20T02:05:25Z"
title: Unauthenticated Kubernetes tool execution in k8s-mcp-server (CVE-2026-130007)
slug: 2026-11-k8s-mcp-server-auth-ghsa-m932-63jc-4jqq
description: The k8s-mcp-server application (prior to 1.1.0) exposes an unauthenticated SSE/HTTP transport by default, allowing remote actors to invoke Kubernetes tools using the server's cluster privileges.
date: "2026-11-20T02:05:25Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:reza-gholizade:k8s-mcp-server:*:*:*:*:*:*:*:*
vendors:
  - reza-gholizade
products:
  - k8s-mcp-server
affected_os:
  - linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Any client that can reach the listening port can enumerate and invoke the server's Kubernetes tools (including destructive/write tools) without credentials.
cves:
  - id: CVE-2026-130007
    epss: 0.0037
    kev_status: "false"
references:
  - https://cveawg.mitre.org/api/cve/CVE-2026-130007
  - https://github.com/advisories/GHSA-m932-63jc-4jqq
action_plan:
  hunt_leads:
    - lead: Search for ingress traffic directed at TCP port 8080 where the HTTP method is POST to /message, specifically looking for payloads that contain the JSON-RPC 'tools/call' method signature without preceding 'Authorization' or 'Bearer' HTTP headers. Further filter for requests originating from external IP ranges rather than local loopback addresses.
      technique_id: T1190
      data_needed:
        - Ingress controller access logs
        - Network flow logs (VPC/NSG)
        - Application layer payload logs (e.g., WAF or API Gateway logs)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Any client that can reach the listening port can enumerate and invoke the server's Kubernetes tools (including destructive/write tools) without credentials.
---

## Overview
k8s-mcp-server versions prior to 1.1.0 contain a vulnerability (CVE-2026-130007) where the default SSE (Server-Sent Events) transport does not require authentication. The server binds to 0.0.0.0:8080 and fails to validate Authorization headers or Origin checks when processing messages, enabling any network-adjacent client to interact with the server's tools.

## Attack Chain
1. The server binds to 0.0.0.0:8080 in its default configuration.
2. An attacker connects to the /sse endpoint to establish a session, which is granted without authentication.
3. The attacker sends POST requests to the /message endpoint; the server performs no authorization or Origin checks before dispatching calls to the `tools/call` handler.
4. The attacker enumerates or executes Kubernetes tools (including state-changing operations like resource creation or Helm management) using the server's configured cluster privileges.

## Impact
Successful exploitation allows an unauthenticated remote attacker to invoke registered Kubernetes tools, executing operations with the server's configured cluster permissions. This may result in unauthorized cluster read and write operations.

## Recommendation
- Upgrade to version 1.1.0 or later, where this issue is resolved.
- Ensure the application is configured to bind only to loopback interfaces (e.g., 127.0.0.1) unless external access is intentionally required.
- When operating over HTTP, place the service behind an authenticating proxy.
