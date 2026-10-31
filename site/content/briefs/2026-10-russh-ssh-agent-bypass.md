---
brief_id: brief-2026-10-31-russh-ssh-agent-bypass
event_id: brief-2026-10-31-russh-ssh-agent-bypass
revision: 1
activity_at: "2026-10-31T03:20:40Z"
title: 'russh: SSH agent fails to require confirmation for keys (CVE-2026-116794)'
slug: 2026-10-russh-ssh-agent-bypass
description: The russh library fails to trigger the Agent::confirm callback for SSH keys protected by the confirm constraint, allowing unauthorized signing operations by any process capable of communicating with the agent.
date: "2026-10-31T03:20:40Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source-provided PoC test confirms the specific regression in server-side agent logic.
cpes:
  - cpe:2.3:a:russh_project:russh:*:*:*:*:*:*:*:*
tags:
  - ssh
  - authentication-bypass
  - rust
  - cve-2026-116794
vendors:
  - Proton
products:
  - russh (< 0.65)
  - Proton Pass desktop
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.004
    subtechnique_name: Private Keys
    evidence: RFC 9987 §10 names it as what stops an attacker with access to the agent from stealing use of those keys.
    confidence_band: high
cves:
  - id: CVE-2026-116794
    kev_status: unknown
references:
  - https://github.com/advisories/GHSA-vp5q-ff62-jwqv
  - https://github.com/Eugeny/russh/commit/3e04597dc54e36bfc85c21996f7d8d9d224e9826
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Upgrade all russh-based applications and dependencies to version 0.65 or later.
      owner: Development
      due: 48h
      evidence: 'Vulnerable: < 0.65'
  hunt_leads:
    - lead: Identify applications in the environment using the russh library versions 0.50.0-beta.12 through 0.64.1.
      technique_id: T1552.004
      data_needed:
        - Software composition analysis (SCA) results or dependency tree output for Rust-based binaries.
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: The vulnerable code is present in every russh release from 0.50.0-beta.12 to 0.64.1.
  mitigation_plan:
    - priority: immediate
      action: Update to russh v0.65+.
      owner: IT Operations
      addresses: CVE-2026-116794
      evidence: Suggested fix provided in the GHSA advisory.
---

The SSH agent server in the `russh` library fails to invoke `Agent::confirm` when handling signing requests for keys added with the `SSH_AGENT_CONSTRAIN_CONFIRM` constraint (commonly applied via `ssh-add -c`). This logic error, introduced in version 0.50.0-beta.12 and persisting through version 0.64.1, replaces the required confirmation check with a hard-coded success result. Applications relying on this callback for security enforcement, such as Proton Pass desktop, do not prompt the user for authorization before performing cryptographic operations, effectively bypassing the protection provided by the confirm constraint.

## Impact

Successful exploitation allows local processes or remote hosts (via SSH agent forwarding) to use protected SSH keys for authentication or data signing without user consent. The private key material itself is not exposed, but the ability to use the key is compromised for as long as an attacker maintains access to the agent socket.

## Recommendation

* Update all software packages using `russh` to version 0.65 or later immediately.
* Review downstream applications that use `russh` to implement agent functionality and verify their `Agent::confirm` logic is invoked correctly.
* For applications that use `confirm` to perform security checks (e.g., "Pass is unlocked" checks), verify that the state logic is not bypassed by the regression.
