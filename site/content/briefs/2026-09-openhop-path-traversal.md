---
title: Path Traversal Vulnerability in @openhop/server
slug: 2026-09-openhop-path-traversal
description: The @openhop/server package is vulnerable to unauthenticated path traversal, allowing remote attackers to read or delete arbitrary YAML files via unsanitized route parameters in the Flow ID endpoint.
date: "2026-09-10T00:50:53Z"
type: threat
types:
  - threat
severities:
  - high
vendors:
  - OpenHop
products:
  - '@openhop/server (0.3.5)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker who can reach the server can read arbitrary .yaml files.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The node process is forced to execute file system operations outside the intended scope.
    confidence_band: med
references:
  - https://github.com/advisories/GHSA-g72f-jw3w-mgh7
rules:
  - title: Detect Path Traversal Attempt in OpenHop Flow API
    description: Detects path traversal attempts against the OpenHop Flow API by identifying double-dot and encoded forward slash sequences in the URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Restrict network access to /api/flows/ to trusted IP ranges.
      owner: IT Operations
      due: 24h
      evidence: Unauthenticated access is enabled by default in Docker containers.
  mitigation_plan:
    - priority: immediate
      action: Implement regex-based sanitization for flow ID parameters.
      owner: Software Engineering
      addresses: CWE-22 Path Traversal
      evidence: Recommended fix provided in GHSA-g72f-jw3w-mgh7.
---

The @openhop/server package (0.3.5 and potentially surrounding versions) is affected by a path traversal vulnerability (CWE-22) originating from the unsafe construction of filesystem paths in `FlowStore.filePath()`. The application concatenates unsanitized HTTP route parameters directly into a `path.join` call without validation. Because the Fastify router (`find-my-way`) automatically decodes URL-encoded characters, an attacker can supply sequences such as `..%2F` to escape the intended `OPENHOP_DATA_DIR` directory.

This vulnerability impacts both the read (GET) and delete (DELETE) operations of the `/api/flows/:id` endpoint. Furthermore, the application registers CORS with `origin: true`, making local instances exploitable via malicious browser-based requests. Default Docker deployments binding to `0.0.0.0` allow direct unauthenticated network access, significantly increasing the risk of data exfiltration and file destruction for exposed instances.

## Attack Chain

1. Attacker sends a crafted HTTP GET or DELETE request to the `/api/flows/:id` endpoint using a traversal payload (e.g., `..%2Ffilename`).
2. The Fastify `find-my-way` router decodes the URL-encoded `%2F` character into a literal `/`, resulting in an `id` parameter value of `../filename`.
3. The `FlowStore.filePath()` method receives the malicious `id` string.
4. The method executes `path.join(this.dir, '../filename.yaml')`, which normalizes to a path outside the designated data directory.
5. The application performs a file system operation (`readFile` for GET or `unlink` for DELETE) on the resulting path.
6. The server confirms the action by returning the contents of the target file or a success status for the file deletion.
7. The attacker succeeds in either exfiltrating sensitive YAML-serialized information or permanently deleting application-critical files.

## Impact

The vulnerability allows unauthenticated attackers to read or delete any `.yaml` file accessible to the user running the OpenHop process. Successful exploitation can lead to the exposure of sensitive application secrets or configuration data (Confidentiality) and the permanent loss of flow configurations (Integrity/Availability). Deployment environments with default Docker settings (`HOST=0.0.0.0`) are reachable directly from the internet, while local instances are vulnerable via cross-origin browser-based exploitation.

## Recommendation

1. Patch immediately by implementing an allowlist validation for the `id` parameter in `packages/server/src/store.ts` using a regex pattern (e.g., `/^[A-Za-z0-9_-]+$/`).
2. If an immediate update is not possible, restrict access to the `/api/flows/` endpoint via network-level firewalls or reverse proxy access control lists to prevent unauthenticated access.
3. Reconfigure the OpenHop deployment to bind to `127.0.0.1` rather than `0.0.0.0` if remote access is not required for the management API.
4. Disable `origin: true` in the CORS configuration within `packages/server/src/index.ts` and replace it with a restrictive allowlist of trusted origins.
