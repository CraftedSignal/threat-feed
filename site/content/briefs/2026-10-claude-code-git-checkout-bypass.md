---
title: Claude Code Plugin Hash Pinning Bypass
slug: 2026-10-claude-code-git-checkout-bypass
description: Claude Code and Claude Desktop failed to verify the integrity of git checkouts during plugin installation, allowing attackers to substitute pinned commits with malicious code via branch name collision.
date: "2026-10-15T22:23:24Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:anthropic:claude_code:*:*:*:*:*:*:*:*
  - cpe:2.3:a:anthropic:claude_desktop:*:*:*:*:*:*:*:*
vendors:
  - Anthropic
products:
  - Claude Code (< 2.1.179)
  - Claude Desktop (< 2.1.179)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195.002
    technique_name: 'Supply Chain Compromise: Compromise Software Dependencies'
    evidence: An attacker controlling a plugin's upstream repository could create a branch named identically to the pinned 40-character SHA, causing the checkout to silently resolve to the attacker's branch tip.
    confidence_band: high
cves:
  - id: CVE-2026-86063
    epss: 0.00171
references:
  - https://github.com/advisories/GHSA-pq7j-f95f-qfcv
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86063
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Claude Code and Claude Desktop to 2.1.179 or later
      owner: IT Operations
      due: 24h
      evidence: Users performing manual updates are advised to update to the latest version.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 2.1.179 or later
      owner: IT Operations
      addresses: CVE-2026-86063
      evidence: 'npm/@anthropic-ai/claude-code (vulnerable: < 2.1.179)'
---

Anthropic's Claude Code and Claude Desktop (v2.1.179 and earlier) contained a vulnerability in the plugin installation flow that allowed attackers to bypass cryptographic hash pinning. The software executed a `git checkout` to retrieve a pinned commit SHA but failed to verify that the resulting HEAD matched the expected identifier. An attacker controlling a plugin's upstream git repository could create a branch named identically to the 40-character commit SHA being pinned. When the client performed the checkout, the git binary silently resolved the reference to the malicious branch tip rather than the intended commit, leading to the execution of unverified, attacker-controlled code within the user's environment. This vulnerability affects all environments where these tools are deployed, including Windows, macOS, and Linux. Users who have enabled automatic updates have already received the patch, while manual installers must ensure they are running versions 2.1.179 or later.

## Impact

Successful exploitation allows for arbitrary code execution in the context of the user running Claude Code or Claude Desktop. Because this occurs during the installation or updating of plugins, the impact is a supply chain compromise where users believe they are installing a specific, verified version of a tool while actually deploying malicious code. This could lead to local data exfiltration, unauthorized API access, or persistence on the developer workstation.

## Recommendation

- Update Claude Code and Claude Desktop to version 2.1.179 or later immediately.
- Review installed plugins in local environments to ensure integrity; verify that the git remotes and current HEADs align with known-good upstream states.
- Audit logs for unexpected `git` process executions originating from the Claude environment if manual updates are lagging behind current deployments.
- Implement a policy to only install plugins from trusted, verified repository sources until all systems are patched to the secure version.
