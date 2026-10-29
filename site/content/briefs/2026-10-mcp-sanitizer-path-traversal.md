---
brief_id: brief-2026-10-29-mcp-sanitizer-path-traversal
event_id: brief-2026-10-29-mcp-sanitizer-path-traversal
revision: 1
activity_at: "2026-10-29T00:17:51Z"
title: 'mcp-sanitizer: Path Traversal via Improper Home Directory Validation'
slug: 2026-10-mcp-sanitizer-path-traversal
description: The mcp-sanitizer library v1.3.3 permits path traversal by whitelisting /home/ and /Users/ in its validation logic, allowing unauthenticated attackers to read sensitive user configuration files.
date: "2026-10-29T00:17:51Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "6"
  rating: A6
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Verified via provided PoC artifacts
products:
  - mcp-sanitizer (v1.3.3)
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker can supply an absolute path to any file under /home/ or /Users/ - requiring no authentication.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Dynamic reproduction confirmed exfiltration of a simulated SSH private key and AWS credentials.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-7w82-6f9j-v9jp
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Audit applications using mcp-sanitizer for file access functionality
      owner: SOC
      due: 24h
      evidence: The library is explicitly designed for use in MCP servers exposed over a network via the Express middleware.
  hunt_leads:
    - lead: Search web server logs for suspicious POST requests to tool endpoints with paths containing home directory fragments
      technique_id: T1059.003
      data_needed:
        - Web server access logs
        - Application-level tool execution logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Dynamic reproduction confirmed exfiltration of a simulated SSH private key and AWS credentials via a single HTTP POST request.
  mitigation_plan:
    - priority: immediate
      action: Implement application-side filtering to block access to sensitive home directory sub-paths
      owner: IT Operations
      addresses: CWE-22
      evidence: Suggested patch removes /home/ and /Users/ from the allowlist and blocks sensitive fragments like /.ssh/ and /.aws/.
---

The mcp-sanitizer library v1.3.3 contains a critical path traversal vulnerability (CWE-22) in its `validateFilePath` function within `src/utils/validation-utils.js`. The library implementation includes an overly permissive allowlist for absolute file paths, explicitly permitting any path starting with `/home/` or `/Users/`. Consequently, security validation fails to block access to highly sensitive files such as SSH keys, AWS credentials, and Kubernetes configurations.

## Attack Chain
1. Attacker sends a POST request to an MCP-enabled application using the `mcp-sanitizer` middleware.
2. The application passes an attacker-supplied `file_path` to `sanitizer.sanitize()`.
3. The `validateFilePath` function normalizes the input and performs an allowlist check.
4. Because the malicious path (e.g., `/home/victim/.ssh/id_rsa`) matches the hardcoded `/home/` prefix, the validator returns `blocked=false`.
5. The library returns the path to the consumer application as a "trusted" sanitized value.
6. The consumer application, trusting the sanitizer's output, performs a filesystem read operation (e.g., `fs.readFile`) on the attacker-controlled path.
7. The application returns the contents of the sensitive file to the attacker in the HTTP response.

## Impact
Successful exploitation allows unauthenticated remote attackers to exfiltrate sensitive user-home directory files, including SSH private keys, cloud provider credentials, and application tokens. This results in complete confidentiality loss for the affected user's data and potential lateral movement into cloud infrastructure or remote systems.

## Recommendation
- Update any application utilizing `mcp-sanitizer` to implement strict path validation that excludes sensitive home directory sub-paths, even if the library is not updated.
- Implement a secondary layer of path validation in the application logic that explicitly denies access to `.ssh`, `.aws`, `.gnupg`, `.kube`, `.config`, and `.env` files regardless of the sanitizer output.
- Audit all MCP server implementations for dependencies on `mcp-sanitizer` and restrict access to the `/tool` endpoint to authenticated and authorized users only.
