---
title: Permission Validation Bypass in Mistral Vibe
slug: 2026-10-mistral-vibe-cve
description: A parsing discrepancy between tree-sitter-bash and the bash shell in Mistral Vibe allows attackers to bypass permission validation via backslash-newline line continuations to execute arbitrary commands.
date: "2026-10-14T04:36:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:mistral_vibe:mistral_vibe:*:*:*:*:*:*:*:*
vendors:
  - Mistral Vibe
products:
  - Mistral Vibe (< 2.25.5)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: Attackers can craft a command string where tree-sitter-bash extracts only an allowlisted prefix such as cd while bash joins the line continuation into a materially different and hidden command.
    confidence_band: high
cves:
  - id: CVE-2026-109428
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109428
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Mistral Vibe to 2.25.5 or later
      owner: IT Operations
      due: 24h
      evidence: Source explicitly mandates version 2.25.5 as the fix for CVE-2026-109428
  mitigation_plan:
    - priority: immediate
      action: Patch Mistral Vibe to version 2.25.5
      owner: IT Operations
      addresses: CVE-2026-109428
      evidence: NVD vulnerability entry
---

Mistral Vibe versions prior to 2.25.5 contain a critical permission validation bypass vulnerability (CVE-2026-109428) originating from the _extract_commands() function in bash.py. The vulnerability arises from a parsing discrepancy between the tree-sitter-bash library and the underlying bash shell when processing backslash-newline line continuations. 

An attacker can craft a malicious input string designed to deceive the application's permission checker. By using line continuation characters, the tree-sitter-bash library parses the command as a benign, allowlisted prefix (such as 'cd'), while the actual bash shell interprets the full string, including hidden commands appended after the newline. This causes the resolve_permission function to grant unauthorized access, leading to arbitrary command execution on the host. This vulnerability has a CVSS v3.1 base score of 8.8, posing a significant risk to environments where Mistral Vibe processes untrusted user input.

## Impact

Successful exploitation allows unauthenticated or unauthorized users to execute arbitrary commands with the privileges of the Mistral Vibe application. This could lead to full system compromise, data exfiltration, or lateral movement within the network. The vulnerability affects all deployments of Mistral Vibe prior to version 2.25.5.

## Recommendation

* Patch Mistral Vibe to version 2.25.5 or later immediately to resolve the parsing logic error in bash.py.
* Audit logs for suspicious bash executions or unusual command line arguments originating from the Mistral Vibe process tree.
* Restrict the permissions of the user account running Mistral Vibe to the minimum necessary level to reduce the impact of potential command injection.
* Review all inputs passed to _extract_commands() for unexpected backslash-newline character sequences that could be used to manipulate bash command interpretation.
