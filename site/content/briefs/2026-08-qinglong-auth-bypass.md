---
title: Authentication Bypass in Qinglong Panel via URL Rewrite
slug: 2026-08-qinglong-auth-bypass
description: An improper authentication vulnerability in Qinglong panel allows unauthenticated remote attackers to reset administrative credentials by leveraging an inconsistent init guard middleware and URL rewrite behavior.
date: "2026-08-20T19:12:15Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - whyour
products:
  - qinglong
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can send PUT /open/user/init with new credentials to reset the admin account on any Qinglong panel instance.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This provides full administrative access, enabling the attacker to execute arbitrary cron jobs and scripts on the server.
    confidence_band: high
cves:
  - id: CVE-2026-3965
    cvss: 6.3
    epss: 0.00441
  - id: CVE-2026-55445
    epss: 0.00404
rules:
  - title: Detect CVE-2026-3965 Exploitation - Unauthenticated Admin Credential Reset
    description: Detects unauthorized attempts to access the Qinglong initialization endpoint via the /open/ path bypass.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all instances of Qinglong panel to version 6bec52dca158 or higher
      owner: IT Operations
      due: 24h
      evidence: Source states patched versions must be >= 6bec52dca158
  hunt_leads:
    - lead: Search web logs for PUT requests to /open/user/init
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This is the primary vector for credential reset
  mitigation_plan:
    - priority: immediate
      action: Restrict access to Qinglong panel interface via WAF or VPN
      owner: IT Operations
      addresses: CVE-2026-3965
      evidence: Exposure of the panel allows unauthenticated access to the initialization endpoint
---

The Qinglong panel contains an authentication bypass vulnerability, tracked as CVE-2026-3965 and CVE-2026-55445, stemming from an incomplete implementation of its initialization security guard. The application uses an 'init guard' middleware to prevent unauthorized access to the `/api/user/init` and `/api/user/notification/init` endpoints once the panel is configured. However, a URL rewrite configuration transforms incoming `/open/*` requests into `/api/*` paths after the guard middleware has already evaluated the request. Because the guard middleware does not account for the `/open/user/init` path, which is explicitly whitelisted from JWT authentication, an unauthenticated attacker can submit a crafted request to reset the panel's administrative credentials. This flaw enables full administrative control over the Qinglong instance, allowing the execution of arbitrary cron jobs and system scripts.

## Attack Chain

1. Attacker identifies a target Qinglong panel instance exposed to the internet.
2. Attacker probes for the `/open/user/init` endpoint to check for reachability.
3. Attacker constructs a PUT request directed at `/open/user/init` containing new desired administrative credentials.
4. The Qinglong application's JWT middleware encounters the request, identifies the `/open/` prefix, and skips authentication as per its whitelist.
5. The init guard middleware processes the request path, fails to find `/open/user/init` in its blocklist, and allows the request to proceed.
6. The `express-urlrewrite` middleware executes, transforming the request URI from `/open/user/init` to `/api/user/init`.
7. The application processes the request as a legitimate initialization call, overwriting existing admin credentials.
8. Attacker logs in with the new credentials to gain full administrative access and schedule malicious tasks.

## Impact

Successful exploitation grants an attacker full administrative access to the Qinglong panel. In many enterprise environments, Qinglong is used to manage cron jobs, scripts, and system automation tasks, meaning this bypass results in the ability to execute arbitrary commands at the privilege level of the application process, potentially leading to full server compromise, data exfiltration, or lateral movement within the network.

## Recommendation

1. Update Qinglong to version >= 6bec52dca158 or the latest stable release to incorporate the fix for CVE-2026-3965 and CVE-2026-55445.
2. Deploy the webserver-based detection rule provided below to identify attempts to access the initialization endpoints via the bypass path.
3. Implement network-level restrictions or VPN access for Qinglong panel interfaces to prevent unauthenticated access from the public internet.
