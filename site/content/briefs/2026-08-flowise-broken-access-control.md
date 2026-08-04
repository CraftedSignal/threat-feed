---
title: Flowise Broken Access Control in /api/v1/files
slug: 2026-08-flowise-broken-access-control
description: A broken access control vulnerability in Flowise versions 3.1.2 and earlier allows authenticated users with low-privileged API keys to list and delete files across different workspaces within the same organization.
date: "2026-08-04T17:25:05Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - Flowise (3.1.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Any authenticated API key within the organization, even one with unrelated permissions, can list and delete files belonging to other workspaces.
    confidence_band: high
cves:
  - id: CVE-2026-69252
references:
  - https://github.com/advisories/GHSA-wp74-f5hh-5f3r
rules:
  - title: Detects CVE-2026-69252 Exploitation - Unauthorized File Deletion in Flowise
    description: Detects DELETE requests to the /api/v1/files endpoint that target paths containing workspace identifiers outside of the user's expected scope.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Flowise to latest version
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-69252 vulnerability in Flowise <= 3.1.2
  hunt_leads:
    - lead: Search logs for multiple successful DELETE requests to /api/v1/files from a single low-privileged API key.
      technique_id: T1078
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Unauthorized file deletion identified in reproduction steps
  mitigation_plan:
    - priority: immediate
      action: Review all active API keys and their assigned permissions in Flowise.
      owner: SOC
      addresses: CVE-2026-69252
      evidence: Vulnerability allows any valid API key to perform unauthorized actions
---

Flowise versions 3.1.2 and earlier contain a broken access control vulnerability (CVE-2026-69252) in the `/api/v1/files` endpoint. The application fails to verify workspace-level permissions, only checking for a general feature flag. Consequently, any authenticated API key - regardless of assigned role - can list and delete files stored in any workspace belonging to the same organization. An attacker with a restricted API key can exfiltrate metadata about files in other workspaces or permanently delete sensitive assets, effectively bypassing the organization's intended workspace isolation boundaries.

## Attack Chain

1. Attacker creates or obtains an API key with minimal permissions (e.g., `tools:view`) via legitimate account access.
2. Attacker inspects the `/api/v1/files` endpoint to identify accessible file paths.
3. Attacker sends a `GET` request to `/api/v1/files` using their low-privileged `Authorization: Bearer` token.
4. The application logic fails to check `activeWorkspaceId`, returning a list of all files across the entire organization.
5. Attacker parses the JSON response to extract paths belonging to target workspaces.
6. Attacker sends a `DELETE` request to `/api/v1/files` with the `path` parameter set to a file located in a foreign workspace.
7. The application performs the deletion using the organization ID context, successfully removing the unauthorized file.

## Impact

Successful exploitation results in the unauthorized exposure of file metadata and destructive tampering of workspace data. An attacker can systematically delete files across an entire organization, leading to significant data loss and disruption of business processes for affected users and workspaces.

## Recommendation

* Update Flowise to a version where CVE-2026-69252 is patched.
* Implement request monitoring for the `/api/v1/files` endpoint to identify users accessing paths outside their assigned workspace directory.
* Deploy the Sigma rule below to detect unauthorized file deletion attempts by low-privileged API keys.
