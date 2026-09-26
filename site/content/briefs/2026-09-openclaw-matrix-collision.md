---
title: Authorization Bypass in @openclaw/matrix via Identifier Collision
slug: 2026-09-openclaw-matrix-collision
description: The @openclaw/matrix npm package (versions 2026.2.2 to 2026.8.0) fails to properly enforce case-sensitivity when deriving authorization identities from Matrix user IDs, potentially allowing unauthorized users to hijack administrative privileges.
date: "2026-09-26T10:59:04Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openclaw:matrix:*:*:*:*:*:*:*:*
tags:
  - supply-chain
  - vulnerability
  - access-control
vendors:
  - OpenClaw
products:
  - '@openclaw/matrix (>= 2026.2.2, < 2026.8.1)'
cves:
  - id: CVE-2026-100541
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100541
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade @openclaw/matrix to version 2026.8.1 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-100541 states the issue is fixed in 2026.8.1
  mitigation_plan:
    - priority: immediate
      action: Patch @openclaw/matrix to version 2026.8.1
      owner: IT Operations
      addresses: CVE-2026-100541
      evidence: CVE-2026-100541 remediation
---

The npm package @openclaw/matrix, used for integrating Matrix protocol communication with OpenClaw systems, contains an authorization vulnerability (CVE-2026-100541). The integration incorrectly applies lowercase normalization to Matrix user IDs during the process of deriving authorization identities. Crucially, this normalization process includes the server-name portion of the ID, which is case-sensitive by protocol definition. 

This logic flaw allows distinct, protocol-valid Matrix user accounts to map to the same internal authorization identity within OpenClaw. A malicious actor who can register or control a user ID that collides with an existing, privileged account via case or Unicode folding can effectively inherit the target's permissions. This grants the attacker unauthorized access to functions such as owner-level commands, plugin approvals, and execution privileges previously assigned to the legitimate user. The issue was addressed in version 2026.8.1.

## Impact

Successful exploitation allows a low-privilege or external user to escalate their permissions to match those of an administrative account defined in the OpenClaw system. This can lead to unauthorized system command execution, unauthorized installation of malicious plugins, and full compromise of the OpenClaw environment. 

## Recommendation

Prioritized, concrete actions for infrastructure and security teams:
- Upgrade the @openclaw/matrix package to version 2026.8.1 or later immediately across all affected deployments.
- Review OpenClaw authorization configurations to ensure that account allowlists and command-approval lists do not contain ambiguous or fold-colliding identifiers.
- Audit existing logs for unauthorized command execution or plugin approval requests originating from Matrix identifiers that deviate in casing from the intended administrative accounts.
