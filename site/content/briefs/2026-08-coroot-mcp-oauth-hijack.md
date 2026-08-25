---
title: Unauthenticated OAuth Client Registration in Coroot
slug: 2026-08-coroot-mcp-oauth-hijack
description: Coroot versions 1.20.2 through 1.24.5 are vulnerable to unauthenticated OAuth dynamic client registration, allowing attackers to hijack user sessions via open redirect and authorization code theft.
date: "2026-08-25T20:49:23Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Coroot
products:
  - coroot
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Attackers can send authorization URLs to signed-in users, capture their authorization codes upon consent approval
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: exchange them for access tokens to hijack MCP sessions
    confidence_band: high
cves:
  - id: CVE-2026-79786
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-79786
  - https://www.vulncheck.com/advisories/coroot-1.20.2-through-1.24.5-unvalidated-redirect-uri-in-mcp-oauth-client-registration
  - https://github.com/coroot/coroot/issues/929
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Coroot to version 1.24.6 or higher
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-79786 affects versions 1.20.2 through 1.24.5
  mitigation_plan:
    - priority: immediate
      action: Restrict access to Coroot API endpoints
      owner: Security Operations
      addresses: CVE-2026-79786
      evidence: Endpoint is unauthenticated
---

Coroot, an open-source observability tool, contains a critical vulnerability (CVE-2026-79786) in its MCP (Machine Configuration Profile) OAuth dynamic client registration endpoint. This endpoint does not perform validation on the redirect URI provided during the client registration process, allowing an unauthenticated attacker to register an arbitrary redirect URI. By sending a crafted authorization URL to a legitimate user, an attacker can trick the user into consenting to access. Upon approval, the application redirects the user's authorization code to an attacker-controlled server. The attacker can then exchange this code for an access token, enabling full session hijacking of the user's MCP session. This vulnerability affects Coroot versions 1.20.2 through 1.24.5.

## Attack Chain

1. Attacker identifies the unauthenticated MCP OAuth dynamic client registration endpoint in the target Coroot instance.
2. Attacker sends an HTTP request to the registration endpoint containing an arbitrary, attacker-controlled redirect URI.
3. The Coroot application registers the malicious client and returns a client identifier to the attacker.
4. Attacker constructs a malicious authorization URL using the obtained client identifier and sends it to a logged-in victim via social engineering.
5. Victim clicks the URL and is presented with an OAuth consent screen within the Coroot interface.
6. Victim approves the request, causing the Coroot server to redirect the victim's browser to the attacker-controlled URI with the valid authorization code in the query parameters.
7. Attacker captures the authorization code from their server logs.
8. Attacker exchanges the authorization code for an access token to gain unauthorized access to the victim's MCP session.

## Impact

Successful exploitation leads to unauthorized access to the victim's MCP sessions. This allows attackers to potentially modify monitoring configurations, access sensitive observability data, or move laterally within the infrastructure monitored by Coroot.

## Recommendation

Prioritized, concrete actions for detection engineering teams:
* Patch Coroot to a version beyond 1.24.5 immediately to remediate CVE-2026-79786.
* Monitor webserver access logs for POST requests to the MCP OAuth registration endpoint originating from unauthorized or external IP ranges.
* Audit existing OAuth client registrations for suspicious redirect URIs pointing to unknown or external domains.
* Restrict access to internal management interfaces to trusted networks to reduce the surface area for unauthenticated API exploitation.
