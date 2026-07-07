---
title: Cortex MCP Server Untrusted Project Bootstrap Code Execution (CVE-2026-49986)
slug: 2026-07-cortex-rce
description: The Cortex MCP server (`neuro-cortex-memory`) is vulnerable to local arbitrary code execution (CVE-2026-49986) when a user opens an attacker-controlled project in the Claude Code IDE and invokes the `open_visualization` tool, allowing an attacker to execute arbitrary Python code with the victim's local user privileges by manipulating the `CLAUDE_PROJECT_DIR` environment variable.
date: "2026-07-03T12:41:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rce
  - lpe
  - supply-chain
  - ide
  - python
  - environment-variable
vendors:
  - Cortex
  - Claude Code
products:
  - neuro-cortex-memory <= 3.17.0
  - Claude Code IDE extension
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Victim opens an attacker-controlled project directory in Claude Code [...] or the attacker otherwise controls CLAUDE_PROJECT_DIR.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Victim invokes `/cortex-visualize` or triggers the `open_visualization` MCP tool (e.g., by selecting a visualization command in the Claude Code interface).
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Cortex to execute an arbitrary `mcp_server/server/visualize_bootstrap.py` from that directory via `subprocess.run([sys.executable, ...])`, achieving code execution with the privileges of the victim's local user process.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: The secondary path through `http_launcher.py` additionally allows the attacker to overwrite files in the Cortex plugin cache directory, potentially establishing persistence that survives after the malicious project is closed.
    confidence_band: med
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: exfiltration of files, secrets, environment variables, and SSH/GPG keys accessible to the local user.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: termination of local processes or destruction of user data.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1561
    technique_name: Disk Wipe
    evidence: modification or deletion of local files, source code, credentials, and plugin caches.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-gvpp-v77h-5w8g
---

A high-severity local arbitrary code execution (LACE) vulnerability, identified as CVE-2026-49986, affects the Cortex MCP server (`neuro-cortex-memory`) versions up to 3.17.0. This flaw arises because the server implicitly trusts the `CLAUDE_PROJECT_DIR` environment variable, which is automatically set by the Claude Code IDE extension to the currently open project directory. An attacker can craft a malicious project containing specific marker files (`mcp_server/` subdirectory and `ui/unified-viz.html`) and an arbitrary Python script named `visualize_bootstrap.py`. When a victim is social-engineered into opening this project in Claude Code and then invokes the `/cortex-visualize` slash command or the `open_visualization` tool, the malicious script is executed with the victim's local user privileges via `subprocess.run()`. This vulnerability allows for sensitive data exfiltration, system manipulation, and potential persistence mechanisms.

## Attack Chain

1.  An attacker crafts a malicious project directory, including specific marker files (`mcp_server/` subdirectory, `ui/unified-viz.html`) and an arbitrary Python script positioned at `mcp_server/server/visualize_bootstrap.py`.
2.  The attacker social-engineers the victim into opening this malicious project within the Claude Code IDE.
3.  Upon opening the project, the Claude Code IDE extension automatically sets the `CLAUDE_PROJECT_DIR` environment variable to the path of the malicious project.
4.  The victim subsequently invokes the `/cortex-visualize` slash command or triggers the `open_visualization` MCP tool within the Claude Code interface.
5.  The `open_visualization` handler in `mcp_server/handlers/open_visualization.py` resolves the path specified by `CLAUDE_PROJECT_DIR` as a trusted Cortex source root, due to the presence of the attacker-controlled marker files.
6.  The handler then constructs a path to the attacker's `visualize_bootstrap.py` script located within the malicious project directory.
7.  The handler executes this malicious `visualize_bootstrap.py` script via `subprocess.run([sys.executable, ...])` with the full privileges of the victim's local user account.
8.  The executed malicious script performs actions such as data exfiltration (e.g., files, secrets, SSH/GPG keys), local file modification, or establishes persistence by overwriting files in the Cortex plugin cache directory via a secondary path in `http_launcher.py`.

## Impact

This vulnerability leads to local arbitrary code execution (LACE) with the privileges of the victim's local user account. Any user with Cortex MCP plugin installed who is tricked into opening an attacker-controlled project in Claude Code and activating the visualization tool is at severe risk. The consequences include, but are not limited to, complete compromise of user data confidentiality through exfiltration of files, secrets, and credentials (e.g., environment variables, SSH/GPG keys). Integrity is also threatened, as attackers can modify or delete local files, source code, and cached data. Furthermore, the attack can impact system availability by terminating local processes or destroying user data. The secondary execution path via `http_launcher.py` enables persistence by allowing attackers to overwrite files in the Cortex plugin cache.

## Recommendation

*   Immediately apply the vendor-recommended remediation to patch `mcp_server/handlers/open_visualization.py` and `mcp_server/server/http_launcher.py` to remove `CLAUDE_PROJECT_DIR` from the dev-source candidate list and gate executable dev-source resolution behind an explicit opt-in flag, as described in CVE-2026-49986.
*   Ensure that all instances of `neuro-cortex-memory` are updated to a version greater than 3.17.0.
*   Educate users about the risks of opening untrusted project directories or repositories in development environments and the potential for social engineering to exploit CVE-2026-49986.
