---
title: Security Matcher Bypass in Network-AI
slug: 2026-08-network-ai-bypass
description: Network-AI versions prior to 5.15.1 are vulnerable to a command injection bypass where inconsistent quote handling between SandboxPolicy and the executor allows attackers to evade blocklist checks.
date: "2026-08-13T12:56:24Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Network-AI
products:
  - Network-AI
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can craft quoted commands that evade blocklist checks and approval gates while the executor runs the identical unquoted dangerous argv.
    confidence_band: high
cves:
  - id: CVE-2026-73615
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73615
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Network-AI to 5.15.1
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-73615 patch release
---

Network-AI versions before 5.15.1 contain a security matcher bypass vulnerability related to how command strings are parsed. The security policy engine, SandboxPolicy, evaluates command strings while preserving original quote characters. In contrast, the subsequent execution engine tokenizes these inputs by stripping the quotes before passing them to the system. An attacker can craft malicious command strings using nested or specific quote patterns that appear benign to the SandboxPolicy blocklist or approval gate. Once the command passes these initial security checks, the executor strips the protective quotes, normalizing the input into a dangerous command string that is then executed. This disparity between the validator and the executor effectively neutralizes input sanitization controls, potentially allowing unauthenticated or authorized users to execute arbitrary commands on systems running the Network-AI software.

## Impact

Successful exploitation allows for the bypass of critical security filters and command blocklists. An attacker can execute arbitrary commands that should have been blocked, potentially leading to unauthorized system access, data exfiltration, or lateral movement within the environment hosting the Network-AI software. The severity is high, as this vulnerability directly undermines the integrity of the application's command execution security boundary.

## Recommendation

- Upgrade Network-AI to version 5.15.1 or later immediately to apply the patch addressing the quote-stripping inconsistency in the executor.
- Review system and application logs for anomalous command patterns involving complex quoting or unexpected shell metacharacters that may indicate attempts to bypass security policies.
- Apply network segmentation for servers hosting Network-AI instances to minimize the impact of potential command injection resulting from this bypass.
