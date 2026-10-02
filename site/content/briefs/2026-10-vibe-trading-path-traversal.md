---
title: Arbitrary File Read Vulnerabilities in Vibe-Trading-AI
slug: 2026-10-vibe-trading-path-traversal
description: Vibe-Trading-AI versions 0.1.0 through 0.1.6 contain path traversal vulnerabilities allowing unauthenticated attackers to read arbitrary files from the container filesystem due to overly permissive sandbox checks and a missing security envelope.
date: "2026-10-02T22:49:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - llm-security
  - cloud-security
  - information-disclosure
products:
  - vibe-trading-ai (>= 0.1.0, < 0.1.7)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Combined with GHSA-1, they are reachable from any anonymous TCP client to port 8899.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1552.001
    technique_name: 'Unsecured Credentials: Credentials In Files'
    evidence: The agent's own secrets and any operator-staged data files [are accessible].
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-5rmq-chc7-m22f
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Vibe-Trading-AI to version 0.1.7 or later
      owner: IT Operations
      due: 24h
      evidence: Remediation provided in source advisory
  mitigation_plan:
    - priority: immediate
      action: Modify Dockerfile to run application as a non-root user
      owner: IT Operations
      addresses: Blast radius of path traversal findings
      evidence: Defense-in-depth recommendation in source
---

Vibe-Trading-AI versions 0.1.0 through 0.1.6 contain two critical file-read vulnerabilities arising from insufficient input validation within its LLM tool registry. The utility `safe_user_path()` in `path_utils.py` incorrectly allows access to any path within the user home directory and current working directory. In the default Docker container deployment, this grants access to sensitive files under `/root` and `/app`, such as `/root/.ssh/id_rsa`, `/root/.aws/credentials`, and `/app/agent/.env`. 

Furthermore, the `read_document()` function in `doc_reader_tool.py` lacks any sandbox enforcement, allowing the application to open and return the contents of any file the process can read, including `/etc/shadow`, `/etc/passwd`, and `/proc/self/environ`. As the application runs as root within the container, these flaws allow unauthenticated attackers to exfiltrate secrets and system configuration files. These vulnerabilities are accessible via TCP port 8899 without authentication, facilitating unauthorized data access and potential full environment compromise.

## Attack Chain

1. Attacker establishes an unauthenticated session with the target Vibe-Trading-AI service on port 8899 via a crafted HTTP POST request.
2. Attacker interacts with the LLM-driven agent by submitting a message containing a request to read or analyze a specific sensitive file path (e.g., `/proc/self/environ`).
3. The agent maps the request to the `read_document()` tool or a tool gated by `safe_user_path()`.
4. The tool fails to perform adequate path validation, bypassing the intended security sandbox due to the lack of restrictive checks in `read_document()` or the overly broad envelope in `safe_user_path()`.
5. The application opens the target file on the host container filesystem with root privileges.
6. The content of the file (e.g., plaintext API keys or shadow passwords) is returned to the agent's message buffer.
7. Attacker polls the session messages to retrieve the full content or the first line of the targeted file, successfully exfiltrating credentials.

## Impact

Successful exploitation allows unauthenticated attackers to read any file on the container filesystem. Observed impacts include the exfiltration of sensitive environment variables (API keys), SSH keys, cloud credentials, and system authentication files like `/etc/shadow`. This leads to the total compromise of the application's security posture and potentially facilitates further lateral movement or unauthorized access to integrated cloud resources.

## Recommendation

Prioritize patching and architectural hardening to mitigate these path traversal risks.

1. Upgrade to Vibe-Trading-AI version 0.1.7 or later to implement the restricted file-read envelopes and input sanitization.
2. Apply the specific code-level remediation: Replace the `Path.home() ∪ Path.cwd()` envelope in `safe_user_path()` with an explicit, restrictive allowlist of directories, and ensure `read_document()` invokes a validated sandbox function prior to file operations.
3. Enforce the Principle of Least Privilege by modifying the Dockerfile to run the FastAPI process as a non-root user (e.g., `USER vibe`) rather than the default root user.
4. Implement network-level access controls to restrict exposure of the agent API port (8899) to trusted IP addresses only.
