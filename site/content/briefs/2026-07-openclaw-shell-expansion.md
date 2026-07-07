---
title: OpenClaw's POSIX Node system.run Safe-Bin Widened by Shell Expansion (GHSA-mhq8-78pj-5j79)
slug: 2026-07-openclaw-shell-expansion
description: A vulnerability in OpenClaw's `system.run` safe-bin feature on POSIX nodes could allow a lower-privilege operator flow to read local files not intended by policy, as shell expansion can alter the interpretation of an approved command, causing a seemingly safe argument to expand into additional shell words and become a file operand, potentially exposing OpenClaw configuration data or other node-local information.
date: "2026-07-03T12:15:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - policy-bypass
  - posix
  - data-exposure
vendors:
  - OpenClaw
products:
  - npm/openclaw (< 2026.5.18)
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A lower-privilege operator flow could cause an approved safe-bin command to read a node-local file that was not intended by the policy.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: A lower-privilege operator flow could cause an approved safe-bin command to read a node-local file that was not intended by the policy.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-mhq8-78pj-5j79
---

A high-severity vulnerability (GHSA-mhq8-78pj-5j79) has been identified in OpenClaw's `system.run` functionality on POSIX nodes, impacting versions prior to `2026.5.18`. The issue arises when the `system.run` command, configured with safe-bin or allowlist-based auto-approval, processes commands where shell expansion can occur. This can lead to a scenario where an argument that appears safe to the policy engine transforms into a file operand after shell expansion, allowing a lower-privilege authenticated operator to read sensitive node-local files unintended by policy. This policy-enforcement gap could be exploited to exfiltrate OpenClaw configuration data or other confidential information stored locally on the node. The vulnerability is specifically limited to paired POSIX node execution and does not represent an unauthenticated node takeover.

## Attack Chain

1.  An authenticated operator, potentially with lower privileges, initiates a `system.run` command on a paired POSIX node.
2.  The `system.run` command is configured with a safe-bin or allowlist-style auto-approval policy.
3.  The operator crafts the command to include parameters susceptible to shell expansion (e.g., variable substitution, wildcard expansion).
4.  The OpenClaw safe-bin check approves the command based on its initial interpretation, before shell expansion.
5.  During execution, the shell processes the command, and its expansion alters the original interpretation of the approved command.
6.  A seemingly safe argument, intended for an approved binary, expands into additional shell words, one of which becomes an unintended file operand to the executed binary.
7.  The executed binary reads a sensitive node-local file (e.g., OpenClaw configuration files, sensitive data) that the operator would otherwise not have authorization to access.
8.  The content of the sensitive node-local file is exposed to the lower-privilege operator flow, bypassing the intended security policy.

## Impact

Successful exploitation of this vulnerability could lead to the unauthorized disclosure of sensitive information from affected OpenClaw POSIX nodes. A lower-privilege operator could read node-local files, including OpenClaw configuration data, API keys, credentials, or other proprietary information. This is a policy-enforcement gap in argument validation, meaning that while the command itself was approved, its post-expansion execution deviates from the intended secure behavior. The extent of the damage depends on the sensitivity of the files accessible by the node process, potentially exposing critical infrastructure details or allowing further lateral movement if credentials are leaked.

## Recommendation

*   Upgrade to OpenClaw version `openclaw@2026.5.18` or later to remediate the vulnerability (GHSA-mhq8-78pj-5j79).
*   Review existing `system.run` policies to avoid broad safe-bin auto-approval for commands that can read arbitrary paths.
*   Prefer explicit approval for node commands that interact with local files, scrutinizing any parameters that could be subject to shell expansion.
