---
title: Path Traversal in @logto/tunnel Service
slug: 2026-08-logto-tunnel-traversal
description: The @logto/tunnel package (v0.3.8 and earlier) is vulnerable to a path traversal attack allowing unauthenticated, remote read access to local files via improper URL sanitization.
date: "2026-08-19T22:33:21Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Logto
products:
  - '@logto/tunnel'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: When the tunnel service is reachable, a requester can use ../ path segments in a static asset request to read files outside that directory that the CLI process can read.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: The observed result is arbitrary file read outside the configured custom UI static directory.
    confidence_band: high
cves:
  - id: CVE-2026-63188
references:
  - https://github.com/advisories/GHSA-rxjr-6c9q-h67x
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63188
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Team
  immediate_actions:
    - action: Update @logto/tunnel to latest version to remediate CVE-2026-63188.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-63188
  mitigation_plan:
    - priority: immediate
      action: Ensure logto-tunnel is bound to localhost only (127.0.0.1) to limit exposure.
      owner: IT Operations
      addresses: CVE-2026-63188
      evidence: The server is started with server.listen(port); bare server.listen(port) binds to all interfaces on this platform.
---

The `@logto/tunnel` CLI tool, commonly used for testing Logto sign-in experiences, contains a high-severity path traversal vulnerability tracked as CVE-2026-63188. The vulnerability resides in the static asset proxy implementation within `packages/tunnel/src/commands/tunnel/utils.ts`. When the tunnel is started with the `--experience-path` flag, the application serves files from this directory using a proxy that fails to validate or normalize incoming request URLs.

By crafting a request containing directory traversal sequences (e.g., `../`), an unauthenticated network actor can escape the intended static file root. Because the server uses `path.join` to resolve the final filesystem path without subsequent containment checks, it directly accesses any file readable by the user process running the tunnel. This is particularly critical when the tunnel is exposed to network interfaces, allowing attackers to exfiltrate local configuration, development environment secrets, or sensitive files from the host machine.

## Attack Chain

1. The target deploys a Logto tunnel service using the `logto-tunnel` CLI and specifies a custom UI directory via the `--experience-path` option.
2. The service binds to a network port (e.g., 9000) on all interfaces, exposing the static proxy functionality.
3. An attacker identifies the accessible tunnel port via network scanning or local internal reconnaissance.
4. The attacker crafts an HTTP request to the tunnel port with a path containing traversal sequences, such as `GET /../../etc/passwd HTTP/1.1`.
5. The `packages/tunnel/src/commands/tunnel/utils.ts` module receives the request and appends the malicious URL directly to the base `staticPath` using `path.join`.
6. The application performs an `fs.open` call on the resulting path, successfully resolving to a file outside the designated root.
7. The tunnel service returns the contents of the requested file in the HTTP response body to the attacker.

## Impact

Successful exploitation allows unauthenticated remote attackers to read arbitrary files from the filesystem of the host running `logto-tunnel`. In development environments where this tool is typically deployed, this can lead to the exfiltration of credentials, API keys, and sensitive project configuration files.

## Recommendation

* Update `@logto/tunnel` to a version containing the patch for CVE-2026-63188.
* Restrict network access to the tunnel service by binding only to `localhost` (127.0.0.1) if remote access is not required for testing.
* Enable web server logs to monitor for requests containing path traversal sequences (`../`) targeting the tunnel port.
* Use network access control lists (ACLs) to block external or unauthorized internal connections to the configured tunnel port.
