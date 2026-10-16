---
title: Blind SSRF in Tandoor Recipes via AI Provider Configuration
slug: 2026-10-tandoor-recipes-ssrf
description: Authenticated users can exploit a blind Server-Side Request Forgery vulnerability in Tandoor Recipes versions prior to 2.6.10 by manipulating AI provider URL inputs to map internal network resources.
date: "2026-10-16T20:44:41Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:tandoorrecipes:tandoor_recipes:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - ssrf
  - reconnaissance
vendors:
  - Tandoor Recipes
products:
  - Tandoor Recipes (< 2.6.10)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The server connects to the supplied provider URL from each AI action and exposes connection success, refusal, or timeout as a blind network-reachability oracle.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: This can reach internal services, other hosts on the server network, and cloud metadata endpoints and map reachable internal hosts and ports.
    confidence_band: high
cves:
  - id: CVE-2026-59970
    cvss: 7.7
references:
  - https://github.com/TandoorRecipes/recipes/security/advisories/GHSA-wq4h-2r8x-cv65
  - https://github.com/TandoorRecipes/recipes/releases/tag/2.6.10
  - https://github.com/TandoorRecipes/recipes/commit/79e783578a5b198a988eb9b486ba19f93df4cfa4
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Tandoor Recipes to version 2.6.10 or later
      owner: IT Operations
      due: 24h
      evidence: Fixed in version 2.6.10
  mitigation_plan:
    - priority: immediate
      action: Restrict outbound network access from the application server using host-level firewall rules or network ACLs to prevent access to internal IPs and metadata services
      owner: IT Operations
      addresses: CVE-2026-59970
      evidence: The vulnerability relies on the server's ability to reach internal network hosts
---

Tandoor Recipes versions prior to 2.6.10 are vulnerable to a blind Server-Side Request Forgery (SSRF) vulnerability. The flaw exists in how the application processes the 'api_base' parameter for AI provider configuration. Specifically, when an authenticated user creates a Space and configures an AI provider, the application fails to apply standard server-side outbound-request validation (safe_request) when interacting with LiteLLM.

By providing a URL targeting internal network services or cloud metadata endpoints, an attacker can force the application server to make unauthorized requests. The application exposes the success, refusal, or timeout status of these requests back to the user interface during AI-driven actions (such as 'ai-import' or 'ai-step-sort'). This creates a blind network-reachability oracle, allowing attackers to map internal infrastructure, identify reachable ports, and potentially access sensitive metadata services within the hosting environment. This issue was resolved in version 2.6.10 by ensuring proper SSRF mitigation on these AI-related API endpoints.

## Attack Chain

1. Attacker authenticates to the Tandoor Recipes instance as a user with Space creation permissions.
2. Attacker accesses the AI provider configuration settings within the Space management interface.
3. Attacker inputs a crafted internal URL (e.g., http://169.254.169.254 or internal service IPs) into the 'api_base' field.
4. Attacker triggers an AI action, such as 'ai-import' or 'ai-step-sort', within the application.
5. The application backend processes the request and sends the malicious 'api_base' URL to the LiteLLM library without validation.
6. The server attempts to connect to the target URL and receives a connection result (success, connection refused, or timeout).
7. The application returns the request outcome to the user interface.
8. Attacker repeats the process with varying ports and target addresses to perform reconnaissance on the internal network.

## Impact

Successful exploitation allows authenticated users to bypass network segmentation and discover internal infrastructure. The vulnerability impacts organizations hosting Tandoor Recipes in environments with access to cloud metadata services or sensitive internal networks, as it facilitates reconnaissance which is a common precursor to further exploitation or data exfiltration.

## Recommendation

- Upgrade Tandoor Recipes to version 2.6.10 or later immediately.
- Apply strict egress filtering on the application server to prevent connections to internal IP ranges (e.g., 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and cloud metadata services (e.g., 169.254.169.254).
- Audit logs for the identified API endpoints (/api/ai-import/ and /api/ai-step-sort/) for unusually high rates of requests or non-standard external/internal URLs in the AI configuration parameters.
