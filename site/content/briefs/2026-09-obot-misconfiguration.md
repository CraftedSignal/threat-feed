---
title: Obot Docker Quickstart Authentication Misconfiguration
slug: 2026-09-obot-misconfiguration
description: Obot versions up to commit d7e6970 contain a default configuration vulnerability that exposes the application with administrative privileges and Docker socket access to unauthenticated network actors.
date: "2026-09-27T23:10:17Z"
lastmod: "2026-09-27T23:11:12Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:obot:obot:*:*:*:*:*:*:*:*
tags:
  - authorization-bypass
  - cve
  - mcp
  - authentication-bypass
  - oauth
  - cve-2026-101062
  - cloud
vendors:
  - Obot
products:
  - Obot (<= d7e6970)
  - obot (< 0.21.1)
  - Obot (<= 0.22.1)
  - Obot (< 0.23.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Any unauthenticated party who can reach the exposed port obtains full administrative access to the Obot API and UI.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The MCP runtime backend reachable this way has access to the host's Docker control surface.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505.004
    technique_name: 'Server Software Component: Docker Socket'
    evidence: Any unauthenticated party who can reach the exposed port obtains full administrative access... including the ability to register and launch attacker-controlled MCP servers.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: An attacker who registers a client pointing at their own domain and induces a logged-in victim to visit a single crafted authorization URL receives an authorization code at the attacker-controlled redirect URI and can exchange it for an access token and refresh token.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers with Power User or higher roles can coerce Obot to make requests to internal services and cloud metadata endpoints, reading responses in error messages to disclose sensitive credentials.
    confidence_band: high
cves:
  - id: CVE-2026-101065
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101065
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101084
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101062
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101064
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Set OBOT_SERVER_ENABLE_AUTHENTICATION=true on all container deployments
      owner: IT Operations
      due: 24h
      evidence: Source documentation for CVE-2026-101065
  mitigation_plan:
    - priority: immediate
      action: Remove /var/run/docker.sock mount from container configurations if not essential
      owner: IT Operations
      addresses: CVE-2026-101065
      evidence: Source documentation warning regarding host docker control surface exposure
updates:
  - at: "2026-09-27T23:10:42Z"
    level: L2
    summary: added coverage for obot (< 0.21.1)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101084
  - at: "2026-09-27T23:11:05Z"
    level: L2
    summary: added coverage for Obot (<= 0.22.1)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101062
  - at: "2026-09-27T23:11:12Z"
    level: L2
    summary: added coverage for Obot (< 0.23.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101064
---

Obot, an open-source AI agent and Model Context Protocol (MCP) platform, contains a critical security misconfiguration in its documented Docker quickstart procedure affecting all versions up to and including commit d7e6970. The default configuration exposes the application on 0.0.0.0:8080 without enabling authentication. By design, unauthenticated requests are assigned to a synthetic 'nobody' user that possesses both Owner and Admin roles within the platform. 

This allows any attacker with network reach to the exposed port to gain full administrative control over the Obot API and UI. Furthermore, the quickstart documentation instructs users to mount the host's /var/run/docker.sock into the container. Attackers gaining administrative access through the Obot interface can leverage this mounted socket to interact with the host's Docker engine, potentially leading to container breakout and full host system compromise. The issue is addressed by updated documentation that mandates enabling authentication via the OBOT_SERVER_ENABLE_AUTHENTICATION environment variable.

## Impact

Successful exploitation allows unauthenticated remote attackers to gain full administrative access to the Obot platform. Due to the mounting of the host Docker socket, an attacker can escalate privileges from the application level to the host operating system. This vulnerability affects any deployment that followed the standard quickstart instructions without manually overriding the default authentication settings.

## Recommendation

Prioritize securing Obot deployments immediately following the documentation update.
- Set the environment variable OBOT_SERVER_ENABLE_AUTHENTICATION=true for all existing Obot containers.
- Review network perimeter controls to ensure the Obot UI and API (port 8080) are not exposed to untrusted networks.
- Verify container mounts to ensure that sensitive host resources, specifically /var/run/docker.sock, are restricted or removed if not strictly required for platform functionality.
- Audit existing Obot logs for unauthorized API access or registry of external MCP servers occurring from unknown or unauthorized client IP addresses.
