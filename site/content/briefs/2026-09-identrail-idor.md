---
title: Identrail Cross-tenant IDOR via GitHub App Installation ID
slug: 2026-09-identrail-idor
description: An improper validation vulnerability in Identrail allows authenticated tenants to perform cross-tenant access to private GitHub repository metadata by supplying an arbitrary installation_id during the connection flow.
date: "2026-09-10T00:50:43Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:identrail:identrail:*:*:*:*:*:*:*:*
tags:
  - idor
  - github
  - cloud
  - saas
vendors:
  - Identrail
products:
  - Identrail (< 1.0.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Identrail's GitHub App connection-completion endpoint binds a fully client-supplied installation_id to the caller's workspace without verifying that the installation belongs to, or was installed by, the workspace that initiated the connect flow.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Attacker now reads the victim org's private repository inventory and can drive posture scans/repo reads via their own workspace.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-cp3j-m783-3ph5
  - https://nvd.nist.gov/vuln/detail/CVE-2026-59185
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Identrail to 1.0.2 or later.
      owner: IT Operations
      due: 24h
      evidence: Source explicitly mandates upgrade to 1.0.2 to fix CVE-2026-59185.
  hunt_leads:
    - lead: Audit connection logs for completion requests originating from unexpected installation IDs.
      technique_id: T1190
      data_needed:
        - API access logs for /github/connect/complete
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The completion route binds client-controlled installation_id without ownership verification.
  mitigation_plan:
    - priority: immediate
      action: Patch Identrail to version 1.0.2.
      owner: IT Operations
      addresses: CVE-2026-59185
      evidence: Vulnerability fixed in v1.0.2.
---

Identrail is affected by an Insecure Direct Object Reference (IDOR) vulnerability (CVE-2026-59185) within its GitHub App connection-completion API. The vulnerability exists because the `POST /v1/workspaces/:workspace_id/projects/:project_id/github/connect/complete` endpoint accepts a client-supplied `installation_id` from the JSON body or the `X-GitHub-Installation-ID` header without verifying that the installation belongs to the workspace initiating the flow. While the application correctly binds a state token to the caller's workspace, it fails to perform a similar check on the installation ID. An authenticated attacker can provide a victim's `installation_id` - which is easily enumerable or discoverable - to link the victim's GitHub organization to the attacker's Identrail workspace. Once linked, the platform mints a GitHub App installation access token using the app's own JWT, granting the attacker unauthorized access to read private repository inventories and potentially perform posture scans on the victim's infrastructure. This affects all versions of Identrail prior to 1.0.2.

## Attack Chain

1. Attacker authenticates to the Identrail platform as a standard tenant.
2. Attacker triggers a legitimate GitHub connection flow via `StartGitHubConnection` to generate a valid `state` token for their own workspace.
3. Attacker identifies the target organization's GitHub App `installation_id` (a non-secret integer available in webhooks or public redirect URLs).
4. Attacker sends a POST request to the completion endpoint (`/github/connect/complete`) using their valid `state` token and the target's `installation_id` in the request header or body.
5. The Identrail backend verifies the `state` matches the attacker's workspace, satisfying the security check, but fails to validate the `installation_id` scope.
6. The platform persists the victim's `installation_id` as a connection owned by the attacker's workspace.
7. Attacker uses Identrail's internal repository listing services (`ListInstallationRepositories`) which mints an access token for the victim's installation.
8. Attacker retrieves private repository lists and metadata from the victim's GitHub account.

## Impact

Successful exploitation results in unauthorized cross-tenant disclosure of sensitive repository metadata and private contents belonging to other customer organizations. This allows attackers to perform reconnaissance on victim organizations' codebase structures, potentially identifying proprietary code or configurations for further targeting.

## Recommendation

1. Upgrade the Identrail platform to version 1.0.2 or later immediately to patch CVE-2026-59185.
2. Perform an audit of existing GitHub App connections to identify any unauthorized or unknown installations linked to your workspaces.
3. Implement strict server-side validation that requires the `installation_id` to be bound to the tenant's identity during the initial GitHub OAuth handshake.
4. Review access logs for the `github/connect/complete` endpoint for requests where the `X-GitHub-Installation-ID` or JSON body `installation_id` differs from those associated with legitimate tenant-authorized installation flows.
